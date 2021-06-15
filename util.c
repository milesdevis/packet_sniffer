#include "util.h"

#include <ctype.h>

void print_packet(const u_char *packet, size_t packet_length, FILE *output)
{
	int i, j, offset;
	int l, r;

	l = packet_length / 16;
	r = packet_length % 16;

	for (i = 0; i < l; i++)
	{
		fprintf(output, "\t\t");

		for (j = 0; j < 16; j += 2)
		{
			offset = (i * 16) + j;
			fprintf(output, "%02x%02x ", packet[offset], packet[offset + 1]);
		}

		fprintf(output, "  ");

		for (j = 0; j < 16; j++)
		{
			offset = (i * 16) + j;

			if (isprint(packet[offset]))
			{
				fprintf(output, "%c", packet[offset]);
			}
			else
			{
				fprintf(output, ".");
			}
		}

		fprintf(output, "\n");
	}

	if (r > 0)
	{
		fprintf(output, "\t\t");

		for (i = 0; i < r; i++)
		{
			offset = (l * 16) + i;

			if (i % 2 > 0)
			{
				fprintf(output, "%02x ", packet[offset]);
			}
			else
			{
				fprintf(output, "%02x", packet[offset]);
			}
		}

		for (i = 0; i < 16 - r; i++)
		{
			if (i % 2 > 0)
			{
				fprintf(output, "  ");
			}
			else
			{
				fprintf(output, "   ");
			}
		}

		fprintf(output, "  ");

		for (j = 0; j < r; j++)
		{
			offset = (l * 16) + j;

			if (isprint(packet[offset]))
			{
				fprintf(output, "%c", packet[offset]);
			}
			else
			{
				fprintf(output, ".");
			}
		}
	}
}
