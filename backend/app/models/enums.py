import enum


class KYCStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    under_review = "under_review"


class Role(str, enum.Enum):
    user = "user"
    admin = "admin"
    reviewer = "reviewer"


class DocumentType(str, enum.Enum):
    aadhaar = "aadhaar"
    pan = "pan"
    passport = "passport"
    driving_license = "driving_license"
    voter_id = "voter_id"
    bank_statement = "bank_statement"
    utility_bill = "utility_bill"


class AuthenticityLabel(str, enum.Enum):
    real = "real"
    fake = "fake"


class VerificationStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    flagged = "flagged"


class ReviewDecision(str, enum.Enum):
    approved = "approved"
    rejected = "rejected"
    request_reupload = "request_reupload"
