// fujitsu_16fx_boot_protocol_sniffer.cpp : Defines the entry point for the console application.
//
// 
// com2com tool were used for MITM serial boot protocol from Fujitsu Flash MCU Programming tool
//


//
// serial.c / serial.cpp
// A simple serial port writing example
// Written by Ted Burke - last updated 13-2-2013
//
// To compile with MinGW:
//
//      gcc -o serial.exe serial.c
//
// To compile with cl, the Microsoft compiler:
//
//      cl serial.cpp
//
// To run:
//
//      serial.exe
//
 
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

unsigned int sum = 0;
unsigned int compare = 0x00ff;

void reset_chk_sum(void) {
	sum = 0;
	compare = 0x00ff;
}

unsigned char get_chk_sum2(void) {
	return 0xff - (unsigned char)(sum & 0xff);
}

unsigned char get_chk_sum(void) {
	unsigned char ret;

	ret = get_chk_sum2();
	
	return ret;
}

void chk_sum(unsigned char data) {
	sum = sum + data;
	if(sum > compare) {
		sum += 1;
		compare += 0x100;
	}
	/*if(sum > 0xffff) {
		sum += 1;
	}*/

}

int main2(void);
 
int _tmain(int argc, _TCHAR* argv[])
{
	main2();
	while(1) Sleep(1);
	return 0;
}

HANDLE hSerial;


int expect(unsigned char *expected_bytes, int size, unsigned char ignore){
	int expected_index = 0;
    unsigned char readed_bytes[5];
	DWORD bytes_readed;

	while(1) {
		if(!ReadFile(hSerial, readed_bytes, 1, &bytes_readed, NULL))
		{
			fprintf(stderr, "Read error\n");
			CloseHandle(hSerial);
			return 1;
		}   
		if(bytes_readed) {
			fprintf(stderr, "%#02x ", (unsigned char)readed_bytes[0]);
			if(expected_index == size) {
				if(get_chk_sum() == readed_bytes[0]) {
					chk_sum(readed_bytes[0]);
					break;
				}
				else {
					expected_index = 0;
				}
			}
			if(readed_bytes[0] != ignore)
				chk_sum(readed_bytes[0]);
			if(expected_bytes[expected_index] == readed_bytes[0]) {
				expected_index++;
			}
		}		
	}
	return 0;
}


#pragma pack (push, 1)
	struct chk_flash_sec {
		unsigned char Addr0;
		unsigned char Addr1;
		unsigned char Addr2;
		unsigned char Count;
		unsigned char Checksum;
	};
#pragma pack (pop)

#pragma pack (push, 1)
	struct dwnld_kern {
		unsigned char Addr0;
		unsigned char Addr1;
		unsigned char Addr2;
		unsigned char CountN;
		unsigned char Checksum;
	};
#pragma pack (pop)

#pragma pack (push, 1)
	struct jmt_to_ram {
		unsigned char Addr0;
		unsigned char Addr1;
		unsigned char Addr2;
		unsigned char Checksum;
	};
#pragma pack (pop)

#define CHECK_FLASH_SEC	0x90
#define DOWNLOAD_KERNEL	0x12
#define READ_KERNEL 0x13
#define LOCK_FLASH	0x0c
#define UNLOCK_FLASH	0x0a
#define JUMP_TO_RAM	0x9f

#define CRC_SIZE	1


int main2(void)
{
    // Define the five bytes to send ("hello")
    unsigned char bytes_to_send[5];
    bytes_to_send[0] = 104;
    bytes_to_send[1] = 101;
    bytes_to_send[2] = 108;
    bytes_to_send[3] = 108;
    bytes_to_send[4] = 111;
 
    // Declare variables and structures
    DCB dcbSerialParams = {0};
    COMMTIMEOUTS timeouts = {0};
         
    // Open the highest available serial port number
    fprintf(stderr, "Opening serial port...");
    hSerial = CreateFile(
                L"\\\\.\\COM4", GENERIC_READ|GENERIC_WRITE, 0, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if (hSerial == INVALID_HANDLE_VALUE)
    {
            fprintf(stderr, "Error\n");
            return 1;
    }
    else fprintf(stderr, "OK\n");
     
    // Set device parameters (38400 baud, 1 start bit,
    // 1 stop bit, no parity)
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (GetCommState(hSerial, &dcbSerialParams) == 0)
    {
        fprintf(stderr, "Error getting device state\n");
        CloseHandle(hSerial);
        return 1;
    }
     
    dcbSerialParams.BaudRate = CBR_38400;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    if(SetCommState(hSerial, &dcbSerialParams) == 0)
    {
        fprintf(stderr, "Error setting device parameters\n");
        CloseHandle(hSerial);
        return 1;
    }
 
    // Set COM port timeout settings
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;
    if(SetCommTimeouts(hSerial, &timeouts) == 0)
    {
        fprintf(stderr, "Error setting timeouts\n");
        CloseHandle(hSerial);
        return 1;
    }

	HANDLE hDownFile;
    hDownFile = CreateFile(
                L"downl_file.bin", GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if (hDownFile == INVALID_HANDLE_VALUE)
    {
            fprintf(stderr, "Error\n");
            return 1;
    }
    else fprintf(stderr, "OK\n");

 
    unsigned char readed_bytes[5];
	DWORD bytes_readed;
	while(1) {
		if(!ReadFile(hSerial, readed_bytes, 2, &bytes_readed, NULL))
		{
			fprintf(stderr, "Read error\n");
			CloseHandle(hSerial);
			return 1;
		}   
		if(bytes_readed == 0) continue;

		fprintf(stderr, "%#02x %#02x ", readed_bytes[0], readed_bytes[1]);
		if(readed_bytes[0]==0x55 && readed_bytes[1]==0x66) break;
		if(readed_bytes[1]==0x55 && readed_bytes[0]==0x66) break;
	}
    fprintf(stderr, "Dial up received...");

    // Send specified text (remaining command line arguments)
    DWORD bytes_written, total_bytes_written = 0;
    fprintf(stderr, "Sending bytes...");
    bytes_to_send[0] = 0x46;
    if(!WriteFile(hSerial, bytes_to_send, 1, &bytes_written, NULL))
    {
        fprintf(stderr, "Error\n");
        CloseHandle(hSerial);
        return 1;
    }   
    fprintf(stderr, "%d bytes written\n", bytes_written);

	{
		unsigned char expected_bytes[] = {0x00, 0x55, 0x00, 0x87, 0x00};
		expect(expected_bytes, sizeof(expected_bytes)/sizeof(expected_bytes[0]), 0x55);
		fprintf(stderr, "\nCalibration off\n");
	}

    bytes_to_send[0] = 0x69;
    if(!WriteFile(hSerial, bytes_to_send, 1, &bytes_written, NULL))
    {
        fprintf(stderr, "Error\n");
        CloseHandle(hSerial);
        return 1;
    }   

	unsigned char frame[0x1000];


unsigned char SEND_OK = 0x69;
unsigned char FLASH_LOCKED = 0x96;
unsigned char FLASH_UNSECURED = 0x69;

	int kernel_size = 0;

	while(1) {
		unsigned char frame_id;
		int expect_count = 0;
		if(!ReadFile(hSerial, &frame_id, 1, &bytes_readed, NULL))
		{
			fprintf(stderr, "Read error\n");
			CloseHandle(hSerial);
			return 1;
		}
		if(!bytes_readed) continue;
		chk_sum(frame_id);

		fprintf(stderr, "frame id=%#02x\n", frame_id);

		if(frame_id == CHECK_FLASH_SEC) {
			expect_count = sizeof(struct chk_flash_sec);
		}
		else
		if(frame_id == DOWNLOAD_KERNEL) {
			expect_count = sizeof(struct dwnld_kern);
			//reset_chk_sum();
		}
		else
		if(frame_id == LOCK_FLASH) {
			expect_count = 2;
		}		
		else
		if(frame_id == JUMP_TO_RAM) {
			expect_count = sizeof(struct jmt_to_ram);
		}		
		else
		if(frame_id == UNLOCK_FLASH) {
			expect_count = 18;
		}				
		
		fprintf(stderr, "expect_count=%d\n", expect_count);

		int i;

read_body:

		for(i = 0; i < expect_count; ) {
			unsigned char readed;
			if(!ReadFile(hSerial, &readed, 1, &bytes_readed, NULL))
			{
				fprintf(stderr, "Read error\n");
				CloseHandle(hSerial);
				return 1;
			}
			if(!bytes_readed) continue;
			frame[i] = readed;
			fprintf(stderr, "%#02x ", readed);

			i++;
			if(i == expect_count) {
				if(get_chk_sum() != readed) {
					fprintf(stderr, "chksum err: %#x expected = %#x\n", readed, get_chk_sum());
				}
			}
			chk_sum(readed);
		}

		expect_count = 0;

		if(frame_id == CHECK_FLASH_SEC) {
			fprintf(stderr, "is flash secured! answer yes\n");
#if 1
			if(!WriteFile(hSerial, &FLASH_LOCKED, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
#else
			if(!WriteFile(hSerial, &FLASH_UNSECURED, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
			if(!WriteFile(hSerial, &FLASH_UNSECURED, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
			chk_sum(FLASH_UNSECURED);
			chk_sum(FLASH_UNSECURED);
			unsigned char sum;
			sum = get_chk_sum();
			chk_sum(sum);
			if(!WriteFile(hSerial, &sum, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
#endif
		}
		else
		if(frame_id == DOWNLOAD_KERNEL) {
			struct dwnld_kern *header = (struct dwnld_kern*)frame;
			fprintf(stderr, "Downl Kernel\n");
			fprintf(stderr, "Addr=%#02x %#02x %#02x CountN=%#02x\n", header->Addr0, header->Addr1, header->Addr2, header->CountN);
			expect_count = header->CountN;
			if(header->CountN == 0)
				expect_count = 256 + CRC_SIZE;
			frame_id = READ_KERNEL;
			goto read_body;
		}
		else
		if(frame_id == READ_KERNEL) {
			fprintf(stderr, "Read kernel bosy ok? answer yes\n");
			if(!WriteFile(hDownFile, frame, i - CRC_SIZE, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
			}
			kernel_size += i - CRC_SIZE;

			if(!WriteFile(hSerial, &SEND_OK, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
		}
		else
		if(frame_id == LOCK_FLASH) {
			fprintf(stderr, "Lock flash? answer ok\n");

			if(!WriteFile(hSerial, &SEND_OK, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
		}
		else
		if(frame_id == JUMP_TO_RAM) {

			
			fprintf(stderr, "\nkernel_size = %d bytes\n", kernel_size);
			fprintf(stderr, "Jump to ram\n");

			CloseHandle(hDownFile);

			if(!WriteFile(hSerial, &SEND_OK, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
		}
		else
		if(frame_id == UNLOCK_FLASH) {
			fprintf(stderr, "secure key ok? answer yes\n");

			if(!WriteFile(hSerial, &SEND_OK, 1, &bytes_written, NULL))
			{
				fprintf(stderr, "Error\n");
				CloseHandle(hSerial);
				return 1;
			}   
		}
	}

	while(1) {
		if(!ReadFile(hSerial, readed_bytes, 1, &bytes_readed, NULL))
		{
			fprintf(stderr, "Read error\n");
			CloseHandle(hSerial);
			return 1;
		}   
		if(bytes_readed) {
			fprintf(stderr, "%#02x ", (unsigned char)readed_bytes[0]);
		}		
	}
    // Close serial port
    fprintf(stderr, "Closing serial port...");
    if (CloseHandle(hSerial) == 0)
    {
        fprintf(stderr, "Error\n");
        return 1;
    }
    fprintf(stderr, "OK\n");
 
    // exit normally
    return 0;
}

