#include <cstdlib>
#include "jssocket.h"
#include "jsocket.h"
#include <iostream>
#include <string>
#include <cstring>
#include <pthread.h>

using namespace std;

const char ini[]={5,1,0};   //SOCKS v5, 1 metodo de autentacación, 0=Sin autenticación
const string tunnel_msg="HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n";
const string errmsg="HTTP/1.1 200 OK\r\n\r\n<html><body><h1>This is a proxy server</h1></body></html>";

int SOCKS_port,HTTP_port;
string SOCKS_host;
bool onlylocal=false;

struct conexiones
{
    jsocket* s;
    jssocketconn* c;
    char* buffer;
};

void *tunel_aux(void* cs_v)
{
    conexiones* cs=(conexiones*)cs_v;
    int recibidos=cs->s->sync_rec(cs->buffer,MAX_TCP_SIZE);
    int enviados_total,enviados;
    while (recibidos>0)
    {
        enviados_total=0;
        do
        {
            if ((enviados=cs->c->sync_send(cs->buffer+enviados_total,recibidos-enviados_total))<=0) break;
            enviados_total+=enviados;
        } while (enviados_total<recibidos);
        if (enviados<=0) break;
        recibidos=cs->s->sync_rec(cs->buffer,MAX_TCP_SIZE);
    }
    cs->c->close_conn();
    cs->s->disconnect();
}

void tunel(jsocket* s, jssocketconn* c, char *b1, char *b2)
{
    conexiones cs={s,c,b2};
    pthread_t aux;
    pthread_create(&aux,NULL,tunel_aux,&cs);
    int recibidos=c->sync_rec(b1,MAX_TCP_SIZE);
    int enviados_total,enviados;
    while (recibidos>0)
    {
        enviados_total=0;
        do
        {
            if ((enviados=s->sync_send(b1+enviados_total,recibidos-enviados_total))<=0) break;
            enviados_total+=enviados;
        } while (enviados_total<recibidos);
        if (enviados<=0) break;
        recibidos=c->sync_rec(b1,MAX_TCP_SIZE);
    }
    c->close_conn();
    s->disconnect();
    pthread_join(aux,NULL);    
}

void tunelHTTP(jsocket* s, jssocketconn* c, char *b1, char *b2)
{
    conexiones cs={s,c,b2};
    pthread_t aux;
    pthread_create(&aux,NULL,tunel_aux,&cs);
    while (true)
    {
        //Procesamos mensaje
        string peticion;
        int petlen=0,posfind;
        do
        {
            int obtenido=c->sync_rec(b1+petlen,MAX_TCP_SIZE-petlen);
            if (obtenido<=0)
            {
                //cout<<"cliente desconectado en mitad de una peticion\n"<<peticion;
                c->close_conn();
                s->disconnect();
                pthread_join(aux,NULL);
                return;
            }
            petlen+=obtenido;
            peticion.assign(b1,petlen);
        } while (peticion.find("\r\n\r\n")==string::npos);
        
        int sizeheader=peticion.find("\r\n");
        string header=peticion.substr(0,sizeheader);
        posfind=header.find(" ");
        string HTTP_op=header.substr(0,posfind+1);
        string HTTP_URL=header.substr(posfind+1,string::npos);
        posfind=HTTP_URL.find(" ");
        string HTTP_VER=HTTP_URL.substr(posfind,string::npos);
        HTTP_URL=HTTP_URL.substr(0,posfind);
        posfind=HTTP_URL.find("://");
        if (posfind!=string::npos)
        HTTP_URL=HTTP_URL.substr(posfind+3,string::npos);
        posfind=HTTP_URL.find("/");
        if (posfind==string::npos)
        {
            HTTP_URL="/";
        }
        else
        {
            HTTP_URL=HTTP_URL.substr(posfind,string::npos);
        }
        HTTP_op.append(HTTP_URL);
        HTTP_op.append(HTTP_VER);
        s->sync_send(HTTP_op.c_str(),HTTP_op.length());
        int enviados,enviados_total;
        enviados_total=sizeheader;
        do
        {
            if ((enviados=s->sync_send(b1+enviados_total,petlen-enviados_total))<=0) break;
            enviados_total+=enviados;
        } while (enviados_total<petlen);
        if (enviados<=0) break;
    }
    c->close_conn();
    s->disconnect();
    pthread_join(aux,NULL);    
}

void *thread_conexion(void* conn)
{
    char buffer[MAX_TCP_SIZE];
    char buffer2[MAX_TCP_SIZE];
    int posfind;
    jssocketconn* client_conn=(jssocketconn*)conn;
    //cout<<"conectado "<< client_conn->getip() <<"\n";
    jsocket socks(SOCKS_host,SOCKS_port);
    if (socks.getconnerror()!=jsocket_no_err)
    {
        //cout<<"Error al conectar al servidor SOCKS\n";
    }
    else
    {
        socks.sync_send(ini,3);
        if (socks.sync_rec(buffer,MAX_TCP_SIZE)!=2)
        {
            //cout<<"La respuesta del servidor SOCKS tiene un tamaño inesperado\n";
        }
        else if (buffer[0]!=5 || buffer[1]!=0)
        {
            //cout<<"La respuesta del servidor SOCKS no es la esperada\n";
        }
        else
        {
            //cout<<"conexion SOCKS ok!!\n";
            string peticion;
            int petlen=0;
            do
            {
                int obtenido=client_conn->sync_rec(buffer+petlen,MAX_TCP_SIZE-petlen);
                if (obtenido<=0)
                {
                    //cout<<"cliente desconectado en mitad de una peticion\n";
                    delete client_conn;
                    return nullptr;
                }
                petlen+=obtenido;
                peticion.assign(buffer,petlen);
            } while (peticion.find("\r\n\r\n")==string::npos);
            
            int sizeheader=peticion.find("\r\n");
            string header=peticion.substr(0,sizeheader);
            posfind=header.find(" ");
            string HTTP_op=header.substr(0,posfind+1);
            string HTTP_URL=header.substr(posfind+1,string::npos);
            posfind=HTTP_URL.find(" ");
            string HTTP_VER=HTTP_URL.substr(posfind,string::npos);
            HTTP_URL=HTTP_URL.substr(0,posfind);
            //cout<< "Op: "<<HTTP_op<<"URL: "<<HTTP_URL<<" ver:"<<HTTP_VER<<"\n";
            
            string host,port;
            short nport;
            
            if (HTTP_op=="CONNECT ")
            {
                posfind=HTTP_URL.find(":");
                host=HTTP_URL.substr(0,posfind);
                port=HTTP_URL.substr(posfind+1,string::npos);
                nport=atoi(port.c_str());
                
                buffer2[0]=5;    //SOCKS v5
                buffer2[1]=1;    //Stream tcp
                buffer2[2]=0;    //Reservado=0
                buffer2[3]=3;    //Direccion=nombre de dominio
                buffer2[4]=host.length();
                memcpy(buffer2+5,host.c_str(),host.length());
                buffer2[5+host.length()]=((char*)&nport)[1];
                buffer2[6+host.length()]=((char*)&nport)[0];
                socks.sync_send(buffer2,7+host.length());
                socks.sync_rec(buffer2,MAX_TCP_SIZE);
                if (buffer2[0]!=5 || buffer2[1]!=0 || buffer2[2]!=0)
                {
                    //cout<<"fallo de la peticion\n";
                }
                else
                {
                    //switch(buffer2[3]) Servidor nos manda tipo de peticion realizada (ipv4, dominio, ipv6,...)
                    client_conn->sync_send(tunnel_msg.c_str(),tunnel_msg.length());     //Mandamos mensaje de conexión establecida al usuario
                    tunel(&socks,client_conn,buffer,buffer2);
                }
            }
            else
            {
                //GET, POST,...
                nport=80;
                posfind=HTTP_URL.find("://");
                if (posfind==string::npos)
                {
                    //Peticion incorrecta, mostramos nuestro mensaje
                    int enviados,enviados_total=0;
                    do
                    {
                        if ((enviados=client_conn->sync_send(errmsg.c_str()+enviados_total,errmsg.length()-enviados_total))<=0) break;
                        enviados_total+=enviados;
                    } while (enviados_total<errmsg.length());
                }
                else
                {
                    HTTP_URL=HTTP_URL.substr(posfind+3,string::npos);
                    posfind=HTTP_URL.find("/");
                    string host;
                    if (posfind==string::npos)
                    {
                        host=HTTP_URL;
                        HTTP_URL="/";
                    }
                    else
                    {
                        host=HTTP_URL.substr(0,posfind);
                        HTTP_URL=HTTP_URL.substr(posfind,string::npos);
                    }
                    HTTP_op.append(HTTP_URL);
                    HTTP_op.append(HTTP_VER);
                    //cout<<HTTP_op<<"\n";

                    buffer2[0]=5;    //SOCKS v5
                    buffer2[1]=1;    //Stream tcp
                    buffer2[2]=0;    //Reservado=0
                    buffer2[3]=3;    //Direccion=nombre de dominio
                    buffer2[4]=host.length();
                    memcpy(buffer2+5,host.c_str(),host.length());
                    buffer2[5+host.length()]=((char*)&nport)[1];
                    buffer2[6+host.length()]=((char*)&nport)[0];
                    socks.sync_send(buffer2,7+host.length());
                    socks.sync_rec(buffer2,MAX_TCP_SIZE);
                    if (buffer2[0]!=5 || buffer2[1]!=0 || buffer2[2]!=0)
                    {
                        //cout<<"fallo de la peticion\n";
                    }
                    else
                    {
                        socks.sync_send(HTTP_op.c_str(),HTTP_op.length());
                        socks.sync_send(buffer+sizeheader,petlen-sizeheader);
                        tunelHTTP(&socks,client_conn,buffer,buffer2);
                    }
                }
            }
                
        }
    }
    //cout<<"desconectado\n";
    delete client_conn;
}

int main(int argc, char** argv) {
    if (argc<4)
    {
        cout<<"Uso: "<<argv[0]<<" {puerto escucha} {host SOCKS5} {puerto SOCKS5} ['local']\n"
                <<"El parametro local es opcional y se introduce sin comillas\nUsalo si solo quieres escuchar peticiones de localhost.\n"
                <<"Ej: "<<argv[0]<< "80 localhost 9050 local\n";
        return 0;
    }
    HTTP_port=atoi(argv[1]);
    SOCKS_host.assign(argv[2]);
    SOCKS_port=atoi(argv[3]);
    for (int i=4;i<argc;i++)
    {
        if (!strcmp(argv[i],"local"))
            onlylocal=true;
        else
            cout<<"No se reconoce el parametro "<<argv[i]<<"\n";
    }
    cout<<"Lanzando proxy HTTP en puerto "<<HTTP_port<<"\nLas peticiones se atienden en socks5://"<<SOCKS_host<<":"<<SOCKS_port<<"\n";
    if (onlylocal)
        cout<<"Solo se escuchan peticiones de localhost\n";
    else
        cout<<"Se escuchan peticiones remotas\n";
    jssocket servidorHTTP(HTTP_port,64,onlylocal);
    if(servidorHTTP.getconnerror()!=jssocket_no_err)
    {
        cout<<"error al iniciar proxy HTTP!\n";
        return 0;
    }
    else
    {
        cout<<"Inicio correcto!\n";
    }

    pthread_t nuevo;
    while (true)
    {
        pthread_create(&nuevo,NULL,thread_conexion,servidorHTTP.connect_client());
        pthread_detach(nuevo);
    }
    return 0;
}

