package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.concurrent.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
//import java.util.Map;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Rip table */
	private ConcurrentLinkedQueue<LocalRIPEntry> ripTable;

	/**queue waiting for arp reply*/
	ConcurrentHashMap<Integer, ConcurrentLinkedQueue<Ethernet>> waitingQueue;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		waitingQueue = new ConcurrentHashMap<>();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	class LocalRIPEntry{
		long startTime;
		RIPv2Entry ripEntry;
		LocalRIPEntry(long t, RIPv2Entry rip){
			this.startTime = t;
			this.ripEntry = rip;
		}
	}

	public void startRip(){
		ripTable = new ConcurrentLinkedQueue<>();
		for (Iface iface : this.interfaces.values()){
			int mask = iface.getSubnetMask();
			int addr = mask&iface.getIpAddress();
			synchronized(this.routeTable){
				this.routeTable.insert(addr, 0, mask, iface);
			}
			RIPv2Entry  ripEntry = new RIPv2Entry(addr, mask, 0);
			ripEntry.setNextHopAddress(iface.getIpAddress());
			LocalRIPEntry localRipEntry = new LocalRIPEntry(-1, ripEntry);
			this.ripTable.add(localRipEntry);
			sendRIPRequest(iface);
		}
		
		TimerTask tUnsol = new TimerTask(){

			@Override
			public void run() {
				for(Iface iface : interfaces.values()){
					sendRIPResponse(null, iface);
				}
			}
		};
		Timer time = new Timer();
		time.schedule(tUnsol,0,10000);

		Thread tTimeout = new Thread(new Runnable(){
		
			@Override
			public void run() {
				while(true){
					for(LocalRIPEntry entry: ripTable){
						if(entry.startTime != -1 && (System.currentTimeMillis()- entry.startTime)>=30000){
							System.out.println("timeout entry :"+IPv4.fromIPv4Address(entry.ripEntry.getAddress()) );
							synchronized(routeTable){
								routeTable.remove(entry.ripEntry.getAddress(),entry.ripEntry.getSubnetMask());
							}
							ripTable.remove(entry);
						}
					}
				}
			}
		});
		tTimeout.start(); 

		
		

	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			//IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			//final int ripAddr = IPv4.toIPv4Address("224.0.0.9");
			// if(ipPacket.getDestinationAddress() ==  ripAddr && 
			// 	ipPacket.getProtocol()== IPv4.PROTOCOL_UDP && 
			// 		((UDP)ipPacket.getPayload()).getDestinationPort()==520){
			// 			this.handleRIPPacket(etherPacket, inIface);
			// 			break;
			// }
				
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket,inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	private void handleRIPPacket(Ethernet etherPacket, Iface inIface){
		IPv4 ip = (IPv4)etherPacket.getPayload();
		UDP udp = (UDP)ip.getPayload();
		RIPv2 ripv2 = (RIPv2)udp.getPayload();
		if(ripv2.getCommand() == RIPv2.COMMAND_REQUEST){
			sendRIPResponse(etherPacket, inIface);
			return;
		}
		if(ripv2.getCommand() == RIPv2.COMMAND_RESPONSE){
			List<RIPv2Entry> entries = ripv2.getEntries();
			for(RIPv2Entry entry: entries){
				int addr = entry.getAddress();
				int mask = entry.getSubnetMask();
				int nextHop = ip.getSourceAddress();
				int metric = entry.getMetric()+1;
				if(metric >= 16){
					continue;
				}
				//int netNum = addr&mask;
				boolean update = false;
				boolean match = false;
				synchronized(ripTable){
					for(LocalRIPEntry lEntry: ripTable){
						if(addr == lEntry.ripEntry.getAddress() && mask == lEntry.ripEntry.getSubnetMask()){
							match = true;
							if(metric < lEntry.ripEntry.getMetric()){
								update = true;
								lEntry.ripEntry.setMetric(metric);
								lEntry.ripEntry.setNextHopAddress(nextHop);
								synchronized(routeTable){
									routeTable.update(addr, mask, nextHop, inIface);
								}
								lEntry.startTime = System.currentTimeMillis();
							}else if(metric == lEntry.ripEntry.getMetric() && nextHop == lEntry.ripEntry.getNextHopAddress()){
								lEntry.startTime = System.currentTimeMillis();
							}
						}
					}
				}	
				if(!match){
					update = true;
					entry.setNextHopAddress(nextHop);
					entry.setMetric(metric);
					ripTable.add(new LocalRIPEntry(System.currentTimeMillis(), entry));
					synchronized(routeTable){ 
						routeTable.insert(addr, nextHop, mask, inIface);
					}
				}
				if(update){
					for(Iface iface : interfaces.values()){
						sendRIPResponse(null, iface);
					}
				}
			}

		}
		System.out.println(this.routeTable.toString());
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        { 
			System.out.println("TTL is zero! pkg drop!");
			sendICMP(etherPacket, inIface, 11, 0,false);
			return; 
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ 
				switch(ipPacket.getProtocol()){
					case IPv4.PROTOCOL_TCP:
						sendICMP(etherPacket, inIface, 3, 3,false);
						break;
					case IPv4.PROTOCOL_UDP:
						UDP udp = (UDP)ipPacket.getPayload();
						if(udp.getDestinationPort()==UDP.RIP_PORT){
							handleRIPPacket(etherPacket, inIface);
							return;
						}
						sendICMP(etherPacket, inIface, 3, 3,false);
						return;
					case IPv4.PROTOCOL_ICMP:
						ICMP icmp = (ICMP)ipPacket.getPayload();
						if(icmp.getIcmpType()==(byte)8){
							sendICMP(etherPacket, inIface, 0, 0, true);
						}
						return;
					default:
						return;
				}
				
			}
        }
		
        // Do route lookup and forward 
        this.forwardIpPacket(etherPacket, inIface);
	}

	private void handleArpPacket(Ethernet etherPacket, Iface inIface){
		//generate arp replies 
		if (etherPacket.getEtherType()!=Ethernet.TYPE_ARP){
			return;
		}
		
		ARP arpPacket = (ARP)etherPacket.getPayload();
		if(arpPacket.getOpCode()==ARP.OP_REQUEST){
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			// MACAddress mac = new MACAddress(arpPacket.getSenderHardwareAddress());
			// arpCache.insert(mac,targetIp);
			if(targetIp == inIface.getIpAddress()){
				sendArpReply(etherPacket, inIface);
			}
		}else if(arpPacket.getOpCode()==ARP.OP_REPLY){
			MACAddress mac = new MACAddress(arpPacket.getSenderHardwareAddress());
			int ip = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			arpCache.insert(mac,ip);
			if(waitingQueue.containsKey(ip)){
				ConcurrentLinkedQueue<Ethernet> q = waitingQueue.get(ip);
				while(!q.isEmpty()){
					Ethernet ePacket = q.poll();
					ePacket.setDestinationMACAddress(mac.toBytes());
					this.sendPacket(ePacket,inIface);
				}
				waitingQueue.remove(ip);
			}
		}	
		System.out.println(this.arpCache.toString());

	}
	
	private void sendICMP(Ethernet etherPacket, Iface inIface, int type, int code, boolean echo){
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int srcIP = ipPacket.getSourceAddress();
		
		//ether header
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toString());
		//set MAC address of nxt hop
		RouteEntry bestMatch = this.routeTable.lookup(srcIP);
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
        { nextHop = srcIP; }
		ArpEntry  arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
        { return; }
        ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

		//ip header
		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		if(echo){
			ip.setSourceAddress(ipPacket.getDestinationAddress());
		}else{
			ip.setSourceAddress(inIface.getIpAddress());
		}
		ip.setDestinationAddress(srcIP);

		//ICMP header
		ICMP icmp = new ICMP();
		if(echo){
			type = 0;
			code = 0;
		}
		icmp.setIcmpType((byte)type);
		icmp.setIcmpCode((byte)code);

		//icmp payload
		Data data = new Data();
		if(echo){
			ICMP echoReq = (ICMP)ipPacket.getPayload();
			data.setData(echoReq.getPayload().serialize());
		}else{
			byte[] a = new byte[4];
			byte[] b = ipPacket.serialize();
			int payloadLength = ipPacket.getHeaderLength()*4+8;
			byte[] icmpPayload = new byte[4+payloadLength];
			System.arraycopy(a, 0, icmpPayload, 0, a.length);
			System.arraycopy(b, 0, icmpPayload, a.length, payloadLength);
			data.setData(icmpPayload);
		}

		//link header together
		icmp.setPayload(data);
		icmp.serialize();
		ip.setPayload(icmp);
		ip.serialize();
		ether.setPayload(ip);
		
		
		
		//send the packet through received interface
		this.sendPacket(ether, inIface);
	}

	private void sendArpRequest(Iface inIface, int requestIp){
		//ether header
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		byte[] a = new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
		ether.setDestinationMACAddress(a);

		
		//arp header
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);

		arp.setOpCode(ARP.OP_REQUEST);

		
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		
		

		byte[] targetHW = new byte[Ethernet.DATALAYER_ADDRESS_LENGTH];
		arp.setTargetHardwareAddress(targetHW);
		arp.setTargetProtocolAddress(requestIp);

		

		//construct packets
		ether.setPayload(arp);

		//sent arp through received inIface
		this.sendPacket(ether, inIface);
	}

	private void sendArpReply(Ethernet etherPacket, Iface inIface){
		
		//ether header
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		
		//arp header
		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte)4);

		arp.setOpCode(ARP.OP_REPLY);
	
		
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		
		

		ARP arpPacket = (ARP)etherPacket.getPayload();
		byte[] srcMac = arpPacket.getSenderHardwareAddress();
		byte[] srcIP = arpPacket.getSenderProtocolAddress();
		arp.setTargetHardwareAddress(srcMac);
		arp.setTargetProtocolAddress(srcIP);
		
		

		//construct packets
		ether.setPayload(arp);

		//sent arp through received inIface
		this.sendPacket(ether, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
		final Iface finalInIface = inIface;
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        { 
			this.sendICMP(etherPacket, inIface, 3, 0,false);
			return; 
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
		{ return; }
		final Iface finalOutIface = outIface;

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
		{ nextHop = dstAddr; }
		final int nxtHop = nextHop;

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nxtHop);
        if (null == arpEntry)
        { 
			if(waitingQueue.containsKey(nxtHop)){
				waitingQueue.get(nxtHop).add(etherPacket);
				return;
			}
			ConcurrentLinkedQueue<Ethernet> tempQ = new ConcurrentLinkedQueue<Ethernet>();
			tempQ.add(etherPacket);
			waitingQueue.put(nxtHop,tempQ);
			// Thread t1 = new Thread(new Runnable(){
			// 	int counter = 0;
			// 	@Override
			// 	public void run() {
			// 		long startime = System.currentTimeMillis();
			// 		while(true){
			// 			if((System.currentTimeMillis()-startime)>=counter*1000){
			// 				if(arpCache.lookup(nxtHop)!=null){
			// 					break;
			// 				}else if(counter == 3){
			// 					Queue<Ethernet> q = waitingQueue.get(nxtHop);
			// 					for(Ethernet e: q){
			// 						sendICMP(e, inIface, 3, 1, false);
			// 					}
			// 					waitingQueue.remove(nxtHop);
			// 					break;
			// 				}else{
			// 					sendArpRequest(inIface, nxtHop);
			// 					counter++;
			// 				}
			// 			}
			// 		}
					
			// 	}
			// });
			// t1.start();
			
			
			TimerTask tk = new TimerTask(){
				int counter = 0;
				@Override
				public void run() {
					if(arpCache.lookup(nxtHop)!=null){
						this.cancel();
					}else if(counter == 3){
						Queue<Ethernet> q = waitingQueue.get(nxtHop);
						for(Ethernet e: q){
							sendICMP(e, finalInIface, 3, 1, false);
						}
						waitingQueue.remove(nxtHop);
						this.cancel();
					}else{
						sendArpRequest(finalOutIface, nxtHop);
						counter++;
					}
					
				}
			};
			Timer time = new Timer();
			time.schedule(tk, 0, 1*1000);
			//this.sendICMP(etherPacket, inIface, 3, 1,false);

			return; 
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
	}
	
	private void sendRIPRequest(Iface inIface){
		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_REQUEST);
		
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		byte[] a = new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
		ether.setDestinationMACAddress(a);
		
		IPv4 ip = new IPv4();
		ip.setTtl((byte)15);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		

		udp.setPayload(rip);
		ip.setPayload(udp);
		byte[] ipPkt = ip.serialize();
		ether.setPayload(ip.deserialize(ipPkt, 0, ipPkt.length));
		
		this.sendPacket(ether, inIface);
	}

	private void sendRIPResponse(Ethernet etherPacket, Iface inIface){
		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_RESPONSE);
		List<RIPv2Entry> entries = new ArrayList<RIPv2Entry>();
		synchronized(ripTable){
			for(LocalRIPEntry entry : ripTable){
				entries.add(entry.ripEntry);
			}
		}
		rip.setEntries(entries);

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		IPv4 ip = new IPv4();
		ip.setTtl((byte)15);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(inIface.getIpAddress());
		if(etherPacket != null){
			ip.setDestinationAddress(((IPv4)etherPacket.getPayload()).getSourceAddress());
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		}
		else{
			byte[] a = new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
			ether.setDestinationMACAddress(a);
			ip.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		}

		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		

		udp.setPayload(rip);
		ip.setPayload(udp);
		byte[] ipPkt = ip.serialize();
		ether.setPayload(ip.deserialize(ipPkt, 0, ipPkt.length));

		this.sendPacket(ether, inIface);
	}
}
