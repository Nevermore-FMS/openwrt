#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>

#define BRIDGE5G "B5"
#define BRIDGE24G "B24"
#define ACCESSPOINT5G "AP5"
#define ACCESSPOINT24G "AP24"
#define BUFFER_SIZE 1024
#define NUMBER_OF_FIELDS 10

int server_fd, client_fd;

#define info(...)        \
  {                      \
    printf(__VA_ARGS__); \
  }
#define panic(...)                \
  {                               \
    fprintf(stderr, __VA_ARGS__); \
    fflush(stderr);               \
    exit(1);                      \
  }

struct Configuration
{
  char *mode;
  u_int16_t team_number;
  char *ssid;
  char *wpa_key;
  bool firewall;
  int bandwidth_limiter;
  bool dhcp_enabled;
  char *unknown_1;
  char *unknown_2;
  char *event_name;
};

char *format(char *template, ...)
{
  va_list args;
  va_start(args, template);
  va_list args1;
  va_copy(args1, args);
  int len = vsnprintf(NULL, 0, template, args);
  char *newstring = malloc(len + 1);
  vsnprintf(newstring, len + 1, template, args1);
  info("%d\n", len);
  va_end(args);
  va_end(args1);
  return newstring;
}

void sig_handler(int signum)
{
  close(client_fd);
  close(server_fd);
}

void reply(char *buf)
{
  int err = send(client_fd, buf, strlen(buf), 0);
  if (err < 0)
    panic("Client write failed\n");
}

void commit_config() {
  system("uci commit wireless");
  system("uci commit network");
  system("uci commit dhcp");
  system("uci commit firewall");
  system("uci commit qos");
  system("uci commit system");
  system("/etc/init.d/dnsmasq restart");
  system("/etc/init.d/network restart");
  info("Committed Changes");
}

void configure_network(struct Configuration config)
{
  char *team_ip_start = format("10.%i.%i\n", config.team_number, config.team_number);

  bool has_security = !strcmp(config.wpa_key, "");
  bool is_24G = config.mode == ACCESSPOINT24G || config.mode == BRIDGE24G;
  bool is_bridged = config.mode == BRIDGE5G || config.mode == BRIDGE24G;

  // Wifi Configuration
  info("Configuring Wifi Networks");
  system(format("uci set wireless.@wifi-iface[0].ssid=%s", config.ssid));
  system(format("uci set wireless.@wifi-iface[1].ssid=%s", config.ssid));
  system(format("uci set wireless.@wifi-iface[0].key=%s", config.wpa_key));
  system(format("uci set wireless.@wifi-iface[1].key=%s", config.wpa_key));

  // TODO: Save Event ID and expiry date.

  info("Configuring Wifi Security: %i", has_security);
  if (has_security)
  {
    system(format("uci set wireless.@wifi-iface[0].encryption=psk2"));
    system(format("uci set wireless.@wifi-iface[1].encryption=psk2"));
  }
  else
  {
    system(format("uci set wireless.@wifi-iface[0].encryption=none"));
    system(format("uci set wireless.@wifi-iface[1].encryption=none"));
  }

  if (is_bridged)
  {
    info("Configuring IP for Bridge");
    system(format("uci set network.stabridge.ipaddr=%s.1", team_ip_start));
    system(format("uci set network.lan.gateway=%s.4", team_ip_start));
    system(format("uci set network.wwan.ipaddr=%s.1", team_ip_start));
    system(format("uci set network.wwan.gateway=%s.4", team_ip_start));
    system(format("uci set network.lan.ipaddr=%s.1", team_ip_start));
    system(format("uci set network.wwan.netmask=255.255.255.0"));
    system(format("uci set network.lan.netmask=255.255.255.0"));

    info("Configuring Wifi Mode for Bridge\n");
    system(format("uci set wireless.@wifi-iface[0].mode=sta"));
    system(format("uci set wireless.@wifi-iface[1].mode=sta"));
    if (is_24G)
    {
      info("Enabling Radio #0 (Is this really 2.4G, needs testing.)\n");
      system(format("uci set wireless.radio0.disabled=0"));
      system(format("uci set wireless.radio1.disabled=1"));
    }
    else
    {
      info("Enabling Radio #1 (Is this really 5G, needs testing.)\n");
      system(format("uci set wireless.radio0.disabled=1"));
      system(format("uci set wireless.radio1.disabled=0"));
    }

    info("Configuring DHCP: %i\n", config.dhcp_enabled);
    if (config.dhcp_enabled)
    {
      system(format("uci set dhcp.apWired.ignore=0"));
      system(format("uci set dhcp.apWireless.ignore=1"));
      system(format("uci set dhcp.apWired.start=200"));
      system(format("uci set dhcp.apWired.limit=20"));
      system(format("uci set dhcp.apWired.dhcp_option=\"1,255.255.255.0 28,%s.255\"", team_ip_start));
      system(format("uci set dhcp.apWireless.dhcp_option=\"1,255.255.255.0 28,%s.255\"", team_ip_start));
      system(format("uci set dhcp.@host[0].ip=%s.2", team_ip_start));
      system(format("uci set dhcp.@host[0].name=roborio-%i-FRC", config.team_number));
    }
    else
    {
      system(format("uci set dhcp.apWired.ignore=0"));
      system(format("uci set dhcp.apWireless.ignore=0"));
    }

    info("Configuring LEDs\n");
    system(format("uci set system.@led[0].sysfs=om5p:red:wifi"));
    system(format("uci set system.@led[1].sysfs=om5p:green:wifi"));
    system(format("uci set system.@led[0].default=0"));
    system(format("uci set system.@led[1].dev=wlan%d", is_24G));
  }
  else
  {
    info("Configuring IP for AP\n");
    system(format("uci set network.stabridge.ipaddr=%s.1", team_ip_start));
    system(format("uci delete network.lan.gateway"));
    system(format("uci set network.wwan.ipaddr=%s.129", team_ip_start));
    system(format("uci delete network.wwan.gateway"));
    system(format("uci set network.lan.ipaddr=%s.1", team_ip_start));
    system(format("uci set network.wwan.netmask=255.255.255.128"));
    system(format("uci set network.lan.netmask=255.255.255.128"));

    info("Configuring DHCP: %i\n", config.dhcp_enabled);
    if (config.dhcp_enabled)
    {
      system(format("uci set dhcp.apWired.ignore=0"));
      system(format("uci set dhcp.apWireless.ignore=0"));
      system(format("uci set dhcp.apWired.start=10"));
      system(format("uci set dhcp.apWired.limit=100"));
      system(format("uci set dhcp.apWired.dhcp_option=\"1,255.255.255.0 28,%s.255\"", team_ip_start));
      system(format("uci set dhcp.apWireless.dhcp_option=\"1,255.255.255.0 28,%s.255\"", team_ip_start));
      system(format("uci set dhcp.@host[0].ip=%s.2", team_ip_start));
      system(format("uci set dhcp.@host[0].name=roborio-%i-FRC", config.team_number));
    }
    else
    {
      system(format("uci set dhcp.apWired.ignore=0"));
      system(format("uci set dhcp.apWireless.ignore=0"));
    }

    info("Configuring Wifi Mode for AP\n");
    system(format("uci set wireless.@wifi-iface[0].mode=ap"));
    system(format("uci set wireless.@wifi-iface[1].mode=ap"));
    if (is_24G)
    {
      info("Enabling Radio #0 (Is this really 2.4G, needs testing.)\n");
      system(format("uci set wireless.radio0.disabled=0"));
      system(format("uci set wireless.radio1.disabled=1"));
    }
    else
    {
      info("Enabling Radio #1 (Is this really 5G, needs testing.)\n");
      system(format("uci set wireless.radio0.disabled=1"));
      system(format("uci set wireless.radio1.disabled=0"));
      system(format("uci set wireless.@wifi-iface[0].ssid=%s_5g", config.ssid));
    }

    info("Configuring LEDs\n");
    system(format("uci set system.@led[0].sysfs=om5p:red:wifi"));
    system(format("uci set system.@led[1].sysfs=om5p:green:wifi"));
    system(format("uci set system.@led[0].default=1"));
    system(format("uci set system.@led[1].dev=wlan%d", is_24G));
  }

  info("Configuring Firewall: %d\n", config.firewall);
  if (config.firewall)
  {
    system(format("uci set firewall.@zone[0].network=\"lan wwan\""));
    system(format("uci set firewall.@zone[1].network="));
  }
  else
  {
    system(format("uci set firewall.@zone[0].network=lan"));
    system(format("uci set firewall.@zone[1].network=wan"));
  }

  info("Configuring QoS: %d\n", config.bandwidth_limiter);
  if (config.bandwidth_limiter)
  {
    system(format("uci set qos.wwan.enabled=1"));
    system(format("uci set qos.wwan.upload=%i", config.bandwidth_limiter));
  }
  else
  {
    system(format("uci set qos.wwan.enabled=0"));
  }

  info("Committing Config...");
  commit_config();
}

void handle_string(char *string)
{
  info("%s\n", string);
  char *token;
  int i = 0;

  struct Configuration config = {
      NULL,
      0,
      NULL,
      NULL,
      false,
      false,
      false,
      NULL,
      NULL,
      NULL};

  while ((token = strsep(&string, ",")) != NULL)
  {
    switch (i)
    {
    case 0:
      config.mode = token;
      break;

    case 1:
      config.team_number = atoi(token);
      break;

    case 2:
      config.ssid = token;
      break;

    case 3:
      config.wpa_key = token;
      break;

    case 4:
      config.firewall = !strcmp(token, "Y");
      break;

    case 5:
      config.bandwidth_limiter = atoi(token);
      break;

    case 6:
      config.dhcp_enabled = !strcmp(token, "Y");
      break;

    case 7:
      config.unknown_1 = token;
      break;

    case 8:
      config.unknown_2 = token;
      break;

    case 9:
      config.event_name = token;
      break;

    default:
      info("Too many values.\n");
      break;
    }

    i++;
  }

  if (i != NUMBER_OF_FIELDS)
  {
    info("Invalid programming message.\n");
    return;
  }

  configure_network(config);

  shutdown(client_fd, SHUT_RDWR);
}

char *form_initial_data()
{
  return "test:test:19.0.1\n";
}

void handle_client()
{
  reply(form_initial_data());
  char *total_string = "";
  char buf[BUFFER_SIZE];

  while (1)
  {
    int read = recv(client_fd, buf, BUFFER_SIZE, 0);

    if (!read || read < 0)
      break; // socket closed

    for (int i = 0; i < strlen(buf); i++)
    {
      char c = buf[i];
      if (c == '\n')
      {
        if (strlen(total_string) > 0)
        {
          handle_string(total_string);

          total_string = "";
        }
      }
      else
      {
        char *temp_string = malloc(strlen(total_string));
        strcpy(temp_string, total_string);
        total_string = malloc(strlen(total_string) + 1);
        strcat(total_string, temp_string);
        strncat(total_string, &c, 1);
      }
    }
    if (strlen(total_string) > 1000)
    {
      panic("Message too long.");
    }
  }
  close(client_fd);
}

int main(int argc, char *argv[])
{
  signal(SIGINT, sig_handler);
  signal(SIGKILL, sig_handler);
  u_int16_t port = 8888;

  struct sockaddr_in server, client;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0)
    panic("Could not create socket\n");

  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = htonl(INADDR_ANY); // Currently I listen on all interfaces, I think this is correct?

  int err = bind(server_fd, (struct sockaddr *)&server, sizeof(server));
  if (err < 0)
    panic("Could not bind socket\n");

  err = listen(server_fd, 128);
  if (err < 0)
    panic("Could not listen on socket\n");

  info("Server is listening on %d\n", port);

  while (1)
  {
    socklen_t client_len = sizeof(client);
    client_fd = accept(server_fd, (struct sockaddr *)&client, &client_len);

    if (client_fd < 0)
      panic("Could not establish new connection\n");

    handle_client();
  }

  return 0;
}
