// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @dev Decentralized Threat Intelligence Registry for TrustLens.
 * Records cryptographic commitments (hashes) of threat investigation reports.
 * 
 * IMPORTANT PRIVACY NOTE (As per HackMatrix PS Module 6):
 * Raw URLs, personal information, email content, and sensitive data REMAIN OFF-CHAIN.
 * Only cryptographic fingerprints (keccak256 / SHA-256) and threat metadata are stored here.
 */
contract ThreatRegistry {
    enum ThreatLevel {
        LowRisk,        // 0
        Suspicious,     // 1
        HighRisk,       // 2
        ConfirmedMalicious, // 3
        Inconclusive    // 4
    }

    struct ThreatReport {
        bytes32 reportHash;      // Cryptographic hash (SHA-256/Keccak) of the full off-chain report
        bytes32 indicatorHash;   // Hash of primary indicator (e.g. hash of domain/URL to allow indexed lookup without exposing raw URL)
        address reporter;        // Address that submitted the report
        uint64 timestamp;        // Submission timestamp
        ThreatLevel threatLevel; // Evaluated risk level
        string category;         // e.g., "Phishing", "Scam", "CertificateTrust", "Malware"
        uint32 disputeCount;     // Number of community disputes registered
        bool isRevoked;          // Whether the report has been invalidated
        bool isVerified;         // Whether authoritative intelligence verified this report
    }

    // Mapping from report hash to the ThreatReport
    mapping(bytes32 => ThreatReport) public reports;

    // Mapping from indicator hash (e.g. keccak256(domain)) to array of associated report hashes
    mapping(bytes32 => bytes32[]) private indicatorReports;

    // Array of all registered report hashes for chronological traversal
    bytes32[] public allReportHashes;

    // Events for transparent audit trail and off-chain indexing
    event ReportRegistered(
        bytes32 indexed reportHash,
        bytes32 indexed indicatorHash,
        address indexed reporter,
        ThreatLevel threatLevel,
        string category,
        uint64 timestamp
    );

    event ReportDisputed(
        bytes32 indexed reportHash,
        address indexed disputer,
        string reason
    );

    event ReportStatusUpdated(
        bytes32 indexed reportHash,
        bool isVerified,
        bool isRevoked
    );

    error ReportAlreadyExists(bytes32 reportHash);
    error ReportNotFound(bytes32 reportHash);
    error Unauthorized();

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Register a new threat report's cryptographic fingerprint on-chain.
     * @param _reportHash The SHA-256 or Keccak-256 digest of the canonical off-chain report JSON.
     * @param _indicatorHash The cryptographic hash of the domain or URL (preserves privacy).
     * @param _threatLevel Categorization of the threat (0: LowRisk to 4: Inconclusive).
     * @param _category Specific category string (e.g., "Phishing").
     */
    function registerReport(
        bytes32 _reportHash,
        bytes32 _indicatorHash,
        ThreatLevel _threatLevel,
        string calldata _category
    ) external returns (bool) {
        if (reports[_reportHash].timestamp != 0) {
            revert ReportAlreadyExists(_reportHash);
        }

        ThreatReport memory newReport = ThreatReport({
            reportHash: _reportHash,
            indicatorHash: _indicatorHash,
            reporter: msg.sender,
            timestamp: uint64(block.timestamp),
            threatLevel: _threatLevel,
            category: _category,
            disputeCount: 0,
            isRevoked: false,
            isVerified: false
        });

        reports[_reportHash] = newReport;
        indicatorReports[_indicatorHash].push(_reportHash);
        allReportHashes.push(_reportHash);

        emit ReportRegistered(
            _reportHash,
            _indicatorHash,
            msg.sender,
            _threatLevel,
            _category,
            uint64(block.timestamp)
        );

        return true;
    }

    /**
     * @notice Verify whether a report hash is registered, its integrity, and current status.
     * @param _reportHash The hash to check.
     */
    function verifyReport(bytes32 _reportHash)
        external
        view
        returns (
            bool exists,
            address reporter,
            uint64 timestamp,
            ThreatLevel threatLevel,
            string memory category,
            uint32 disputeCount,
            bool isRevoked,
            bool isVerified
        )
    {
        ThreatReport storage r = reports[_reportHash];
        if (r.timestamp == 0) {
            return (false, address(0), 0, ThreatLevel.Inconclusive, "", 0, false, false);
        }
        return (
            true,
            r.reporter,
            r.timestamp,
            r.threatLevel,
            r.category,
            r.disputeCount,
            r.isRevoked,
            r.isVerified
        );
    }

    /**
     * @notice Retrieve all report hashes associated with a hashed indicator.
     */
    function getReportsForIndicator(bytes32 _indicatorHash)
        external
        view
        returns (bytes32[] memory)
    {
        return indicatorReports[_indicatorHash];
    }

    /**
     * @notice Flag/dispute an existing report for community review.
     */
    function disputeReport(bytes32 _reportHash, string calldata reason) external {
        ThreatReport storage r = reports[_reportHash];
        if (r.timestamp == 0) revert ReportNotFound(_reportHash);

        r.disputeCount += 1;
        emit ReportDisputed(_reportHash, msg.sender, reason);
    }

    /**
     * @notice Update verification/revocation status of a report (curator/owner action).
     */
    function updateReportStatus(bytes32 _reportHash, bool _isVerified, bool _isRevoked) external {
        if (msg.sender != owner) revert Unauthorized();
        ThreatReport storage r = reports[_reportHash];
        if (r.timestamp == 0) revert ReportNotFound(_reportHash);

        r.isVerified = _isVerified;
        r.isRevoked = _isRevoked;

        emit ReportStatusUpdated(_reportHash, _isVerified, _isRevoked);
    }

    /**
     * @notice Returns total number of registered reports.
     */
    function getTotalReportsCount() external view returns (uint256) {
        return allReportHashes.length;
    }
}

