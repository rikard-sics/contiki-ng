<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2023090101">
  <simulation>
    <title>EDHOC simulation</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>Client</description>
      <source>[CONFIG_DIR]/edhoc-client/edhoc-test-client.c</source>
      <commands>$(MAKE) TARGET=cooja clean
      $(MAKE) -j$(CPUS) DEBUG=1 COOJA_CONSOLE_OUTPUT=1 edhoc-test-client.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiCFS</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiEEPROM</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="-41.29379881633341" y="84.55841010196319" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>1</id>
        </interface_config>
      </mote>
    </motetype>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>Server</description>
      <source>[CONFIG_DIR]/edhoc-server/edhoc-test-server.c</source>
      <commands>$(MAKE) TARGET=cooja clean
      $(MAKE) -j$(CPUS) DEBUG=1 COOJA_CONSOLE_OUTPUT=1 edhoc-test-server.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiCFS</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiEEPROM</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="-14.358887920221928" y="84.18613975939073" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>2</id>
        </interface_config>
      </mote>
    </motetype>
  </simulation>
  <plugin>
    org.contikios.cooja.plugins.Visualizer
    <plugin_config>
      <moterelations>true</moterelations>
      <skin>org.contikios.cooja.plugins.skins.IDVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.GridVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.TrafficVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.UDGMVisualizerSkin</skin>
      <viewport>1.696847649207872 0.0 0.0 1.696847649207872 238.2029835403895 36.46408356383216</viewport>
    </plugin_config>
    <bounds x="1" y="1" height="400" width="400" z="5" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config>
      <filter />
      <formatted_time />
      <coloring />
    </plugin_config>
    <bounds x="400" y="160" height="478" width="681" z="2" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.TimeLine
    <plugin_config>
      <mote>0</mote>
      <mote>1</mote>
      <showRadioRXTX />
      <showRadioHW />
      <showLEDs />
      <zoomfactor>500.0</zoomfactor>
    </plugin_config>
    <bounds x="0" y="829" height="166" width="1081" z="4" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.Notes
    <plugin_config>
      <notes>Enter notes here</notes>
      <decorations>true</decorations>
    </plugin_config>
    <bounds x="680" y="0" height="160" width="401" z="3" />
  </plugin>
  <plugin>
    org.contikios.cooja.serialsocket.SerialSocketServer
    <mote_arg>1</mote_arg>
    <plugin_config>
      <port>60002</port>
      <bound>true</bound>
      <commands>[CONFIG_DIR]/test-edhoc.sh [CONTIKI_DIR] 45</commands>
    </plugin_config>
    <bounds x="28" y="423" height="116" width="362" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>
TIMEOUT(10000000000);
sim.setSpeedLimit(100000.0);  // Simulation speed.

while (true) {
  log.log(id + " " + msg + "\n");  // Write all output to COOJA.testlog

  // Define the device type using a ternary operator
  var device = (id == 1) ? "Client" : (id == 2) ? "Server" : "Unknown";
  device = "[MSG : EDHOC     ] " + device;

  // Check if the OSCORE master secret is correct
  if (msg.contains("OSCORE Master Secret")) {
    if (msg.contains("OSCORE Master Secret (16 bytes):f9 86 8f 6a 3a ca 78 a0 5d 14 85 b3 50 30 b1 62")) {
      log.log("C " + device + ": Correct master secret!\n");
    } else {
      log.log("I " + device + ": Incorrect master secret!\n");
    }
  }
  
  // Check if the OSCORE master salt is correct
  if (msg.contains("OSCORE Master Salt")) {
    if (msg.contains("OSCORE Master Salt (8 bytes):ad a2 4c 7d bf c8 5e eb")) {
      log.log("C " + device + ": Correct master salt!\n");
    } else {
      log.log("I " + device + ": Incorrect master salt!\n");
    }
  }

  // Check if PRK_4e3m is correct
  if (msg.contains("PRK_4e3m")) {
    if (msg.contains("PRK_4e3m (32 bytes): 81 cc 8a 29 8e 35 70 44 e3 c4 66 bb 5c 0a 1e 50 7e 01 d4 92 38 ae ba 13 8d f9 46 35 40 7c 0f f7")) {
      log.log("C " + device + ": Correct PRK_4e3m!\n");
    } else {
      log.log("I " + device + ": Incorrect PRK_4e3m!\n");
    }
  }

  // Check if info for SALT_4e3m is correct
  if (msg.contains("info SALT_4e3m")) {
    if (msg.contains("info SALT_4e3m (37 bytes):05 58 20 ad af 67 a7 8a 4b cc 91 e0 18 f8 88 27 62 a7 22 00 0b 25 07 03 9d f0 bc 1b bf 0c 16 1b b3 15 5c 18 20")) {
      log.log("C " + device + ": Correct info for SALT_4e3m!\n");
    } else {
      log.log("I " + device + ": Incorrect info for SALT_4e3m!\n");
    }
  }

  // Check if SALT_4e3m is correct
  if (msg.contains("SALT_4e3m")) {
    if (!msg.contains("info SALT_4e3m")) {
      if (msg.contains("SALT_4e3m (32 bytes):cf dd f9 51 5a 7e 46 e7 b4 db ff 31 cb d5 6c d0 4b a3 32 25 0d e9 ea 5d e1 ca f9 f6 d1 39 14 a7")) {
        log.log("C " + device + ": Correct SALT_4e3m!\n");
      } else {
        log.log("I " + device + ": Incorrect SALT_4e3m!\n");
      }
    }
  }
  
  // Check if TH_4 is correct
  if (msg.contains("TH4")) {
    if (msg.contains("TH4 (32 bytes):c9 02 b1 e3 a4 32 6c 93 c5 55 1f 5f 3a a6 c5 ec c0 24 68 06 76 56 12 e5 2b 5d 99 e6 05 9d 6b 6e")) {
      log.log("C " + device + ": Correct TH_4!\n");
    } else {
      log.log("I " + device + ": Incorrect TH_4!\n");
    }
  }
  
  // Check if PRK_out is correct
  if (msg.contains("PRK_out")) {
    if (msg.contains("PRK_out (32 bytes): 2c 71 af c1 a9 33 8a 94 0b b3 52 9c a7 34 b8 86 f3 0d 1a ba 0b 4d c5 1b ee ae ab df ea 9e cb f8")) {
      log.log("C " + device + ": Correct PRK_out!\n");
    } else {
      log.log("I " + device + ": Incorrect PRK_out!\n");
    }
  }
  
  // Check if PRK_exporter is correct
  if (msg.contains("PRK_exporter")) {
    if (msg.contains("PRK_exporter (32 bytes): e1 4d 06 69 9c ee 24 8c 5a 04 bf 92 27 bb cd 4c e3 94 de 7d cb 56 db 43 55 54 74 17 1e 64 46 db")) {
      log.log("C " + device + ": Correct PRK_exporter!\n");
    } else {
      log.log("I " + device + ": Incorrect PRK_exporter!\n");
    }
  }

  // Check for finish condition
  if (msg.contains("Client time to finish")) {
    log.testOK();
  }
  YIELD();
}
</script>
      <active>true</active>
    </plugin_config>
    <bounds x="1037" y="40" height="700" width="600" z="1" />
  </plugin>
</simconf>
