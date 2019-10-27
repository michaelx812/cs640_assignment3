package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
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
				if(ipPacket.getProtocol()==IPv4.PROTOCOL_TCP ||
				ipPacket.getProtocol()==IPv4.PROTOCOL_UDP){
					this.sendICMP(etherPacket, inIface, 3, 3,false);
				}else if(ipPacket.getProtocol()==IPv4.PROTOCOL_ICMP){
					ICMP icmp = (ICMP)ipPacket.getPayload();
					if(icmp.getIcmpType() == 8){
						this.sendICMP(etherPacket, inIface, 0, 0, true);
					}
				}
				return; 
			}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
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
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		
		//send the packet through received interface
		this.sendPacket(ether, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
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
			System.out.println("packet sent");
			this.sendICMP(etherPacket, inIface, 3, 0,false);
			return; 
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { 
			this.sendICMP(etherPacket, inIface, 3, 1,false);
			return; 
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}
