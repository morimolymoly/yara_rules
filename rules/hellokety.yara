rule hellokety_apt10 {
    meta:
        author = "Mizuho Mori"
        created_date = "2023-06-16"
        modified_date = ""
        hash1 = "02b95ef7a33a87cc2b3b6fd47db03e711045974e1ecf631d3ba9e076e1e374e9"
        hash2 = "3ad1a9770a533c2bb8be9d4e7150a2a167d0709c4b0339a5fd6a511008cea7ef"
        hash3 = "b2561c624e2f980e500abe6188f4f4b46e46a57642ec1c3829ce4d2d4bda9588"
        purpose = "hunting"
        description = "hunting APT10 or APT10-Nexus APT Group's samples"

    strings:
        $kety = "c:\\users\\hellokety.ini"
    condition:
        $kety
}