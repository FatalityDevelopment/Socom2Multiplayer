using System;

namespace DNAS;

/// <summary>
/// DNAS protocol configuration. TLS credentials and socket configuration
/// belong to their corresponding transport layers.
/// </summary>
public sealed class DnasServerConfiguration
{
    public string? ConsoleHex;
    public string? DiscHex;
    public string? Serial;
    public string TicketRoot = "RSA";
    public string? RepositoryUrl;
}

/// <summary>
/// Creates the DNAS session registry, ticket loader and response producers.
/// This class contains no transport logic or per-title cryptographic material.
/// </summary>
public static class DnasServerFactory
{
    public static DnasSessionRegistry Create(DnasServerConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        ProofInputPlan? pinnedIdentity = GetPinnedIdentity(configuration);
        DnasResponseProducer responses = new();
        TicketStore tickets = new(configuration.TicketRoot, configuration.RepositoryUrl);

        return new DnasSessionRegistry(pinnedIdentity, secondProducer: responses.ProduceSecondReply, finalProducer: responses.ProduceFinalResult, firstProducerFactory: (request, proof) => CreateFirstReplyProducer(request, proof, responses, tickets));
    }

    private static ProofInputPlan? GetPinnedIdentity(DnasServerConfiguration configuration)
    {
        if (configuration.ConsoleHex == null)
            return null;

        return ProofInputPlan.PrepareNormalBoot(configuration.Serial!, Convert.FromHexString(configuration.ConsoleHex), Public.ParseDnasId(configuration.DiscHex!));
    }

    private static DnasServerSession.FirstReplyProducer CreateFirstReplyProducer(byte[] request, NativeLiveC1Report proof, DnasResponseProducer responses, TicketStore tickets)
    {
        // The ticket is selected using the serial decoded from the client's
        // validated C1. A missing title ticket never falls back to another one.
        C1Packet packet = (C1Packet)DnasPackets.Parse(request);
        byte[] ticket = tickets.GetOrFetch(proof.Identity.GameSerial, packet);

        // The ticket is immutable for this session even when later C2/C3
        // arrive over different TCP/TLS connections.
        return (initial, decoded) => responses.ProduceFirstReply(initial, decoded, null, ticket);
    }
}
