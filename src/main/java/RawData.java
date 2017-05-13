

import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RawData {

    public static class RawDoc {

        public String id;
        public String headline;
        public String description;

        public RawDoc(String id, String headline, String description) {
            this.id = id;
            this.headline = headline;
            this.description = description;
        }        

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(id).append(", ").append(headline).append(", ").append(description);
            return sb.toString();
        }
        
        
    }

    public static class SRQuery {
        public int srId;
        public String problemDetails;
        public String problemDescrptn;

        public SRQuery(int srId, String problemDetails, String problemDescrptn) {
            this.srId = srId;
            this.problemDetails = problemDetails;
            this.problemDescrptn = problemDescrptn;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(srId).append(", ").append(problemDetails).append(", ").append(problemDescrptn);
            return sb.toString();
        }
    }
    
    private final static String[][] _docs = { 
    { "1", "Some URLs configured with category/reputation block rule are not blocked on onbox managed device", "Two sites, hustler.com and securepctuneup.com have a category of 65534 in Firewall Engine Debug, however, on Brightcloud.com, they are in two separate categories on Brightcloud.com. Both are not being blocked by Access Control Policy configured with category and reputation block rule and URL look-up configured."}, 
    { "2", "Clear counters on Fabric Interconnect NXOS clears but eventually returns to previous count", "While performing a &quot;clear counters&quot; from NXOS it was observed that the counters went to zero as expected. After a short time the counters returned to their previous count"}, 
    { "3", "Consult calls are hung in the RSM VLenginetestEngineServlet.jsp Url if Hold Action is invoked", "n the VleNgineServelt URL the CallId's which are related to the Consult Call will get Struck in CONNECTED status under the SkillGroup"}, 
    { "4", "Replaced disk shown in stcli command as unavailable, vCenter shows the same disk as offline", "Replaced disk shown in stcli command as unavailable, vCenter shows the same disk as offline, there are also 2 blacklisted disks"}, 
    { "5", "Lync application sharing should result in different floorctrl  attribute values in SDP from IVY", "Conference, established by the use of the multisite feature on endpoints registered to CUCM, result in failed screen sharing from Lync if the Lync client is the first called participant."}, 
    { "6", "B200 M4 doesnt share interface is down when its disabled from linux OS and experiences packet drops", "Receiving Drops on a disabled/unconfigured interface (from OS perspective) in linux. From UCSM perspective it does not recognize that the link is down."}, 
    { "7", "UCCX 11.5 - IVR Outbound CCDR Report does not capture call with answering machine redirect to IVR", "When the campaign Answering Machine Treatment configured is set to End Call the call data is displayed in the IVR Outbound CCDR Report.But when the campaign Answering Machine Treatment is configured to Transfer ASM calls to IVR, the call data is not displayed at all or is extremely inconsistent. It shows up arbitrarily in the reports. Most of the calls don't show up."}, 
    { "8", "Getting an error java.lang.StringIndexOutOfBoundsException while creating a group variable.", "When creating group variables within Tidal that contain single quotes, double quotes, and parentheses the group variables do not properly save and throws this error in the logs"}, 
    { "9", "Sessmgr task restarts on assert failure when handling a PDN disconnect req under unknown conditions", "Stack (83816@0xfffe9000)"}, 
    { "10", "REDIRECT ACL not Applied to clients in local mode APs of a flexconnect local switching WLAN 8.3.102", "The clients connected to any local mode AP in a Flexconnect local switching WLAN are not able to get redirected because the AAA ACL is not applied."}, 
    { "11", "Traffic hits policer in priority queue when marked by class-default of ingress policy on an SVI", "Traffic is hitting the policer of an Egress policy which it should not after the traffic is marked by an ingress policy-map applied to an SVI which is matching using class-default"}, 
    { "12", "C220 M4, C240 M4 Power Supply Input Lost for system using the raid adapter battery/capacitor backup", "This bug is created for system using the raid adapter battery/capacitor backup and reporting error message on the PSU, as follows"}, 
    { "13", "After CSM upgrade to 4.11, VPN S2S tunnels changed from interface IP address to Manual IPv6 address", "Customer upgraded CSM from 4.10 to 4.11 SP2 ."}, 
    { "14", "host discovery of IPv4 addresses not working w/ v. 6.1 FMC, older version managed Firepower devices", "Host discovery within the Firepower System does not properly detect IPv4 IP addresses if the Firepower Management Center runs software version 6.1, and the Firepower devices managed by the FMC runs a software version lower than 6.1. The host records and discovery events on the FMC will display either no IP address at all, or what appears to be an IPv6 address -- likely, a malformed address."}, 
    { "15", "Alias address in Processing Details on tracking is not changed when multiple recipient used", "When address which rewrite by aliasconfig on ESA is used 2nd or later recipients on message,"}, 
    { "16", "USB1 / slot 0 format prompts for password when logged in with network-admin user privilege", "switch# sh users"}, 
    { "17", "High CPU observed on ASA installed on FPR9300 with just around 100,000 CPS due to HA replication.", "We are observing a high CPU on ASA installed on a FPR9300 platform with SM-36 security module with just around 100,000 CPS which is way too less when compared to the datasheet number of 800,000 CPS."}, 
    { "18", "Unable to set replication timeout and process timeout on 11.5.1SU1 and later version using CLI", "while executing the below CLI's on both publisher and subscriber after upgrading unity connection from 10.5.2->11.5SU1"}, 
    { "19", "Outgoing ACL get hit by the traffic generated by/from the switch itself while using Denali IOSes", "C3650 running Denali IOS (16.3.1 & 16.3.2) with an outgoing ACL applied on a SVI drops traffic generated by the switch itself (echo-reply) which didn't happen in previous IOS-XE (3.7.3)."}, 
    { "20", "'No action' and exiting when attempting to delete the IOS Device Ports during OpsPurgeLocation", "'No action' and exiting when attempting to delete the IOS Device Ports during OpsPurgeLocation"}, 
    { "21", "Show the available status of the 3260 and don't show them for manual association if unavailable", "Issue Summary"}, 
    { "22", "Channel guide interaction with channel up/down commands channel change behavior not identical.", "Reference"}, 
    { "23", "'Security Appliance Data Transfer Status' in System Status page doesnt show all quarantines enabled", "'Security Appliance Data Transfer Status' in 'System Status' page doesn't show all Service enabled when viewed under Management Appliance -> Centralized Services -> System Status -> 'Security Appliance Data Transfer Status'"}, 
    { "24", "AnyConnect Client Certificate Authentication does not work when client sends SHA2 Certificate", "Message type warning sent to the user"}, 
    { "25", "[ENH]-Creation of WSA Web User Interface User Accounts based on Active Directory Group Membership", "[ENH]-Creation of WSA Web User Interface User Accounts based on Active Directory Group Membership."}, 
    { "26", "Sessmgr restarts on assert failure during back-to-back PTMSI attach of a just released PTMSI", "Assertion failure at sess/sgsn/sgsn-app/db/sgsn_db_pmm.c"}, 
    { "27", "MCU is changed if an endpoint from \"Participant templated\" is added to an existing conference", "User is creating a conference and manually assigns the MCU to this conference and saves it."}, 
    { "28", "Discovered template from wireless controller needs to add controller name as suffix or prefix", "The problem is if multiple wireless controllers are defined in the Prime and we discover template from these controller, they are saved under My templates but we do not know as to which template belongs to which controller"}, 
    { "29", "681316889- Should be a way to check if the box is getting connected to agent we want it to be.", "Customer is running a re-occurring job on prod server and just few of its instances started running on dev server, starting from 12 midnight until the dev server was shut down."}, 
    { "30", "Cisco 78xx-3PCC phone having issue upgrading to Enterprise FW version as well as to MR 10.4(1)", "When customer upgrading the 78xx-3PCC phone (FW load"}, 
    { "31", "CLI login before main process is ready, results in \"Unknown command or missing feature key\"", "This is to document a behavior that does not seem to be documented so far to save time for customer and CSE running into the problem."}, 
    { "32", "IKEv2 - Signature sign, verify failures seen with 4096 bit certificates with onboard crypto engine", "DMVPN deployment."}, 
    { "33", "No tasks are routed to agent when he is working on non-interruptible task and makes an outbound call", "we initiated 2 chats and assigned to agent X."}, 
    { "34", "The latest version of TrendMicro is not included in the latest anyconnect Compliance Module", "The following"}, 
    { "35", "Jabber 11.7.0 Chats tab Notification badge message count does not clear after message read", "Received offline chats remain marked as unread after reading."}, 
    { "36", "Show commands filtering using \"include\" returns lines which doesn't match the regular expression", "Show commands filtering using &quot;include&quot; command after pipe returns lines which doesn't match the regular expression"}, 
    { "37", "Sessmgr restarts on failed assert when sending RAB Assignment Req under certain conditions", "********************* CRASH #03 ***********************"}, 
    { "38", "Sessmgr restarts on failed assert when handling MBR for a dedicated bearer under certain conditions", "Looks like similar trace of CSCux42501. Only changed &quot;esm t3485-timeout 5&quot;"}, 
    { "39", "HyperFlex installer compute-node service profiles do not include local disk in boot policy", "When creating compute-only node service profiles from the HX template and not booting ESXi from SD cards, the server will not boot to the OS if it is installed on local disk"}, 
    { "40", "Swim Diff reports are stretched horizontally out of the window need to scroll right to view", "The reports were stretched horizontally and make scrolling over to the right and left add extra time to validate. This was due to ?show vlan brief? output having a lot of vlans included and therefore all on one line....instead of being wrapped around to the next line."}, 
    { "41", "Prevent Local LAN DNS server IP from being tunneled when DNS IP is a part of the split-tunnel-list", "This bug has been opened to account for the scenario where the Local LAN subnet is not a part of the split-tunnel supernet but the DNS server IP is. With the fix of CSCtj82339, if the Local LAN is a subnet of the split-tunnel-list, it is exempted from tunneling. However there are cases where the Local LAN and the DNS server IP for the Local LAN are on different subnets. To account for such cases also, we would like for the DNS server IP to be considered separately for exclusion."}, 
    { "42", "Unable to add AD user for ACS login if \"pwd must not contain pwd or its characters in reverse order\"", "We would like to put an AD user as super admin with &quot;Password may not contain <Password>&quot;; this policy is configured under System Administration>Users>Authentication Setting. If we try to add an AD user ACS is not allowing us to add with above authentication settings"}, 
    { "43", "WSA strips Range header for pipelined HTTP request when Safe Search/Site Content Rating is enabled", "Customer(Microsoft) informed us that they see high bandwidth utilization at certain times of day, which causes bandwidth saturation and starts to introduce latency in the network. The customer has all AVC policies set to MONITOR. However, safe search and site content rating is set to BLOCK."}, 
    { "44", "[apic syslog] Changes to existing Syslog Remote Destination configuration requires mgmt restart", "In the multiple releases of ACI firmware, there is an issue with deploying Syslog policy changes to existing Syslog Remote Destination configurations.  One example of the the issue can be observed when the admin user changes the UDP port# used for the Syslog Remote Destination. The configuration change is accepted but not applied.  Syslog messages continue to be sent on the previously configured UDP Port.  To force the APIC to use the modified configuration changes, you have to restart the mgmt policies with the CLI command &quot;acidiag restart mgmt&quot;."}, 
    { "45", "Firepower System documentation incorrectly describes where to enable communications with Cisco CSI", "The URL Filtering Configuration options have moved in Version 6.0 on ASDM and FireSIGHT from Local Configuration to Cisco CSI Configuration. However, the online help documentation has not been updated to reflect this fact."}, 
    { "46", "Sessmgr restarts on assert failure when handling Delete Session Request under unknown conditions", "SW Version"}, 
    { "47", "CVP Reporting Guide Current and Historical Callback Report document incorrect reporting interval", "The section on the &quot;Current and Historical Callback Report&quot; in the CVP Reporting Guide incorrectly states pending callbacks are records from the last 15 minutes and historical are records from greater than 15 minutes. This information conflicts with the database schema guide which states the interval as 30 minutes. Confirmed with DE that 30 minutes is the correct value."}, 
    { "48", "Absolute/Idle timeout functionality not working after unplanned DPC migration for ehrpd calls", "1. With 19.3.4 (63957)  on DPC setup with KDDI config, create eHRPD session."}, 
    { "49", "enhance MRA user level authentication throttling to include failed authentication attempts", "Enhance MRA user level authentication throttling to include failed authentication attempts"}, 
    { "50", "Cisco IOS XE Software for Cisco ASR920 Zero Touch Provisioning Denial of Service Vulnerability", "A customer with an ASR-920-24SZ-M running asr920-universalk9_npe.03.16.00.S.155-3.S-ext is crashing repeatedly due to a segmentation fault in the DHCPD Receive process. The crashes have been happening since 2/25 and always happen in pairs with two crashes occurring about 7-10 minutes apart."}, 
    { "51", "e2e Server needs to be manually restarted after power outage to resolve issue with Diagnostics tool.", "After power outages both the Apocalypse and Ivana experienced the following problems when trying to run the Diagnostics tool"}, 
    { "52", "Unable to import .dev file of deleted device - duplicate device and/or locked by user error message", "Customer accidentally deleted one of their firewall from CSM 4.7 Patch 2 and when they restored the DB on their lab CSM with same version and exported the device and tried to import it back on production CSM, they got the duplicate device and u413xxx user activity message which blocked the import of .dev file."}, 
    { "53", "Sessmgr restart on failed assert when sending DelSessRequest to old SGW under certain conditions", "The following Sessmgr Crash is reported in StartOS 19.3.5 (64198)."}, 
    { "54", "ISE External Syslogs sent to Remote Logging Target for profiling events append a '\' to some logs", "When configuring a remote logging target for Syslog and setting logging category Profiler to DEBUG for this target, some logs are prepended with a '\' in front of the comma and causing issues when parsing via CSV on the External Syslog server because the fields do not match."}, 
    { "55", "Evaluation of Apache HTTPD Web Server Request Headers Denial of Service Vulnerability(CVE-2016-8740)", "A vulnerability(CVE-2016-8740) in Apache HTTPD web server could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on a targeted server."}, 
    { "56", "WC When scrolling Available Actions in Job Events Built In Actions constantly show in list", "In the Web Client-Job Events, when you scroll thru the Available Actions, the built-in Actions are to be at the bottom.  These keep showing in the list before the custom actions are displayed.  With a sizable number of custom actions this causes the list to load slower."}, 
    { "57", "DE250-P1- IVPN - unsubscribe/delete of a CPE - removes the device from VMS but doesn't remove...", "IVPN - unsubscribe/delete of a CPE - removes the device from VMS but doesn't remove the configuration from the CPE device-->still stays connected and configured in the customer tenant but not shown in VMS."}, 
    { "58", "Anyconnect NAM ,dot1x does not work with 3850 when defaut EAP timers and MAB order configured", "Anyconnect Default EAP Timers not working with 3850 Switches when configured  for"}, 
    { "59", "ASA failover not replicating ACL optimization elements correctly to mate with high amount of ACEs", "ASA running 9.1.7.4 and configured with a large DB of ACL elements (+2M) is not replicating from the active member to the standby device the amount of entries that collapsed into the single entry, which in turn causes the standby unit to display the incorrect hash.  Example below"}, 
    { "60", "UCSM GUI, Password copy-paste disabled in 3.1(2c) impacting customers who use password managers", "Earlier to 3.1.2, users could copy/paste the password to UCSM GUI. Since 3.1.2 this feature not working or disabled by intention. This has many drawbacks to customers, specially for all who use password manager."}, 
    { "61", "\"setup-timeout\" pgw-service option mentioned in documentation for rel 17 and rel16 but not available", "Based on the release notes of release 18, the &quot;setup-timeout&quot; configuration option was introduced for PGW service first time in release 18 with CSCuo61706."}, 
    { "62", "MID call state transition from Talking>Held>Not Ready>Reserved>Talking is not handled in Finesse", "Race condition between sequence of events,"}, 
    { "63", "Prime Infrastructure does not display UI correctly for \"show all Template\" in dot11a-RRM Intervals", "Prime Infrastructure does not display correctly display the Configuration->templates->features & Technologies, when going into the Controller->802.11a or n or nac->dot11a-RRM->intervals, if you have templates already there and use the I that is circled and click on &quot;show all templates&quot; the UI does not display correctly."}, 
    { "64", "Customer requesting CISCO-WIRELESS-NOTIFICATION-MIB notification table be added to tech docs.", "Documentation to provide a mapping of entries from the CISCO-WIRELESS-NOTIFICATION-MIB notification table entries into the technical documentation explaining SNMP Traps for Prime Infrastructure for northbound alarms."}, 
    { "65", "Unable to modify scale ACL used for PBR with BFD when TCAM utilization is around 34% with atomic upd", "Module/Release"}, 
    { "66", "Nexus 9508 is not differentiated under inventory & licensing as it displays as 9500 switch", "A fully synced Nexus 9508 without any collection failure is advertised as a Nexus 9500 Switch under inventory and does not show up under the licensing Dashboard."}, 
    { "67", "681440002 / TES 6.2.1 Unused column in CM Operations/Alerts screen in WC called \"JobOwner\"", "Plugin Version# 6.2.1.566"}, 
    { "68", "Option to reject the MBReq/UPC when IMEI in MBreq/UPC different than the session present in PGW", "This is related to MFL 5007 . As discussed with BU , BU suggested to open cdets ."}, 
    { "69", "VNTAG and 802.1q tags present in replicated traffic when performing RX Span of Fex HIF ports.", "When SPAN/ERSPAN is used to capture the RX traffic on the Fex HIF ports, additional  are present in the captured traffic."}, 
    { "70", "Recovery of a DCM encoder part of a resilient-reserved pool fails with to a StackOverFlowError", "Refer to http"}, 
    { "71", "incorrect boot variable set to 800 series routers when insertboot command is enabled during swim job", "while trying to push an image through PI to 892 series router with insert boot command option enabled, incorrect boot is being set"}, 
    { "72", "Nexus 9300-EX switches will drop encapsulated traffic from itself for all protocols except ICMP.", "Starting in 1.3(2) code a check was implemented on all nexus 9k hardware that would drop encapsulated traffic if the leaf received its own TEP as both source and destination. The typical scenario where this would be seen would be when a host in an EPG that is connected to leaf A tries to ping an SVI that is configured on leaf A but is in a different VRF. The leaf will receive the traffic and send to the spine proxy's TEP. The spine will rewrite the destination TEP to LEAF A so that now the source and destination TEP addresses are the overlay loopback address on LEAF A. When LEAF A receives the traffic it will drop it with the following istack_kpm_trace log message (enabled by 'debug istack trace filter all' from root)"}, 
    { "73", "SUP crash due to Assert fail in cable_cardstate_is_card_ready - slightly different with CSCur32470", "This issue is very similar to CSCur32470, but slightly different. The root cause is the same ? an assert in macro CABLE_CHECK_LC_SLOT due to invalid destination slot. The fix for CSCur32470 prevented this issue from happening in L2-DOCSIS related IPC messages. This new issue happens in an IPC message from a different module."}, 
    { "74", "When attempting to manage team resources in Cisco Finesse Administration page a number of teams report errors", "When the in-memory cache for config data gets out of sync with the team data, Finesse cannot recover from it without a restart"}, 
    { "75", "Failure in updating QCI after TAU, during 3G to 4G handover when eRAB modify Request is rejected", "see BigDescription"}, 
    { "76", "ENH Health alert and syslog when high percentage of URL cloud lookups relative to database", "If the sensor is unable to load the bcdb file, URL filtering may continue to work based on the &quot;Query cloud for unknown URL&quot; feature, causing the customer to be unaware of the bcdb issue. This is an enhancement request for a sensor syslog and health alert when a high percentage of URLs are using the cloud lookup feature."}, 
    { "77", "Generate alarm notifying when AP hasn't had clients connected to it for a certain amount of time", "Generate alarm notifying when AP hasn't had clients connected to it for a certain amount of time"}, 
    { "78", "Filter in Job Definition for Enabled or Disabled - click default and still maintains the filter", "Filter in Job Definition for Enabled or Disabled - click default and still maintains the filter"}, 
    { "79", "Add a note - Unregistering UCS domain with UCS Central doesnot revert policies from global to local", "Add a note to the UCS Central Guide, under working with UCS Manager -"}, 
    { "80", "\"Rule may be skipped until the application or URL can be determined for rule\" not present in 6.0 +", "Adding the description from the dupe bug"}, 
    { "81", "Sessmgr restarts on failed assert during Iu release under some conditions yet to be analysed", "Crash seen multiple times."}, 
    { "82", "iMessage traffic not detected by P2P plugin 2.1.701 on Apple's ios 10.2 when downloading content", "iMessage detection is not working properly with iPhone 5s, SW 10.2 when downloading content."}, 
    { "83", "Blind Conferences with recording, JTAPI handling CallConferenceChangedEvent with party DN updated", "Scenario. When a monitored agent 1 with a call to agent 2 places a blind conference to an external caller we would expect to see a CallCtlConnEstablishedEv event when the external participant answers the call. However JTAPI Client does not send this event. As a result we report the conference segment with 2 participants (Agent1 and Agent2) in CONNECTED state, and the external participant in NETWORK_ALERTING state. Therefore, JTAPI needs to handle the CallConferenceChangedEvent with the party DN updated. currently, JTAPI only handles the scenarios where the state of the call changes."}, 
    { "84", "When browsing the Serviceability (feature Services) page of Sub from Pub, we see CPU pegging", "When going to the Feature Services/Network Services page of the Subscriber from the Publisher CUCM server, we see a CPU spike."}, 
    { "85", "StarOS continues to send RADIUS test probes to manually disabled Server and not marked down", "Customer issued the the command &quot;disable radius server for port 1645&quot; expecting the system to stop sendign RADIUS Probe messages to the far server.  A PCAP provided by the Customer and testing in HTTS Lab system confirmed the system continues to send RADIUS Probe Test messages to the far end server even though it has been disabled in the StarOS CLI."}, 
    { "86", "Name of the called party Should be displayed on the calling phone if user is added in the Directory", "+ Phone A calls Phone B"}, 
    { "87", "Adaptor, Equipment and Fault MIBs stop working = No Such Object available on this agent at this OID", "Customer getting error response when trying to SNMP walk using the following MIBs"}, 
    { "88", "Routing policies don't match for Transparent HTTPS requests in Connector mode with certain config", "Log Description"}, 
    { "89", "CUIC 11.0.1 Agent Login Logout Activity Report Can't be Exported to SFTP Using the Scheduler", "++ Agent Login Logout Activity Report Can't be Exported to SFTP Using the Scheduler"}, 
    { "90", "Async list does not clear properly when no responce is recieved to a GetEncryptInfo request.", "In the OCAI PA async operation was added to assist Customer for EAS event in large systems.  This introduced a bug where the list of outstanding Async messages does not clear an entry when no response at all is received to a sent request.  The result is that the list eventually fills and additional requests are failed with a Status 0xb."}, 
    { "91", "Re-Establishing broken jdbc link between CPS and mysql server requires qns service restart", "We have a situation with customer"}, 
    { "92", "Dual QFP Crash triggered by removing service policy from interface with mixed shaper feature enabled", "Dual QFP Crash triggered by removing service policy from interface with mixed shaper feature enabled"}, 
    { "93", "[4092] Failed to verify if the CUCM and IM and Presence Service versions match on 9.1.1.41900-1", "&quot;Error"}, 
    { "94", "Duplicated Loc groups in 3.0>3.1 upgrade for grps created using checkbox on campus creation form", "When a location group for a campus is created in 3.0 by checking the &quot;create location group&quot; checkbox and the"}, 
    { "95", "88xx IP phones do not display call pickup alert or play call pickup alert audio on non-prime line", "If an 88xx IP phone has a line that is not the prime line added to a call pickup group with the Call Pickup Group Notification Policy set to Audio and Visual Alert, the call pick up alarm should be played, and the alert displayed. This only happens if the prime line is in the pickup group, if the line in the pickup group is not the prime line, this does not happen appropriately."}, 
    { "96", "UCCX - CUIC 11.5 unable to configure users in the \"User List\" page if the user name start with \"u\"", "Steps to reproduce"}, 
    { "97", "Some devices will not will not link up when connected to Mgig ports on catalyst 3850 or 4500", "When connecting some devices to mgig ports on 3850 mgig models or 4500 line cards that support mgig functionality, the port will fail to correctly link up."}, 
    { "98", "DOC ISE VM installation can't be done if disk is greater than or equals to 2048 GB or 2 TB", "As per http"}, 
    { "99", "Failure when processing single chassis device (BK = NA) followed by a composite (same IP Address)", "Note"}, 
    { "100", "mDNS Policy filtering not being applied when AP group names contain partial same characters", ""}, 
    { "101", "UCS Server Power ON action not working when the server was gracefully shutdown from vCenter", "SR# 680816759 / BEMS504386"}, 
};

    public static Set<RawDoc> getSamples() {
        Set<RawDoc> docs = new HashSet<>();
        for (String[] doc : _docs) {
            docs.add(new RawDoc(doc[0], doc[1], doc[2]));
        }
        return docs;
    }
    
    public static Set<RawDoc> getDocs() {
        Set<RawDoc> docs = new HashSet<>();
        String qry = "SELECT identifier, headline, description FROM full_bugs WHERE length(headline) between 90 and 500";
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(
                    "jdbc:postgresql://localhost:5432/test", "colm_mchugh", "Infy123+");
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(qry);
            while (rs.next()) {
                docs.add(new RawDoc(rs.getString(1), rs.getString(2), rs.getString(3)));
            }
            connection.close();
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(RawData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(RawData.class.getName()).log(Level.SEVERE, null, ex);
        }
        int i = 0;
            System.out.println("private final static String[][] _docs = { ");
            for (RawDoc doc : docs) {
                i++;
                System.out.println("    { \"" + i + "\", \"" + doc.headline + "\", \"" + doc.description + "\"}, ");
                if (i > 100) {
                    break;
                }
            }
            System.out.println("};");

        return docs;
    }

    public static Set<SRQuery> getQrys() {
        Set<SRQuery> qrs = new HashSet<>();
        String qry = "SELECT input_file, problem_details, problemdescription FROM full_260k";
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(
                    "jdbc:postgresql://localhost:5432/test", "colm_mchugh", "Infy123+");
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(qry);
            while (rs.next()) {
                qrs.add(new SRQuery(rs.getInt(1), rs.getString(2), rs.getString(3)));
            }
            connection.close();
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(RawData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(RawData.class.getName()).log(Level.SEVERE, null, ex);
        }
        return qrs;
    }
    
    public boolean testConnection() {
        try {
            // Test connection to the database.
            Class.forName("org.postgresql.Driver");
            Connection connection = null;
            connection = DriverManager.getConnection(
                    "jdbc:postgresql://localhost:5432/test", "colm_mchugh", "Infy123+");
            assert connection != null;
            connection.close();
            return true;
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(RawData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(RawData.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
}
