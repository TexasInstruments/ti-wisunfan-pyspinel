class spinel_utilities():

    def set_bit_at_position(self, position, data):
            mask = 1 << position
            return data | mask

    def change_format_input_string(self, original_input):
        byte_array_str_list = str(original_input)
        byte_array_input_string = ''

        count = 0
        for value in original_input:
            if(count != 0):
                byte_array_input_string += ':'
            append_str = value[2:]

            # if only one digit is present, add another 0
            if(len(append_str) == 1):
                append_str = '0' + append_str

            byte_array_input_string += append_str
            count += 1

        return byte_array_input_string

    def format_display_string(self, line):
        display_string = ''
        count = 0
        for char in line:
            if(count % 2 == 0) and count != 0:
                display_string += ':'
            
            display_string += char
            count += 1
        return display_string

    def convert_to_chan_num_list(self, line):
        values = line.split(':')
        total_num_channels = 129
        hex_string = ''
        binary_string = ''
        count = 0
        for v in values:
            if(' ' in v):
                v = v.split(' ')[0]

            # Step 2: Convert the string to a hex number
            hex_num = int(v, 16)

            # Step 3: Invert the binary values if needed (we do not use this feature)
            new_value_first = 0
            new_value_last = 0

            inverted_hex_num = hex_num
            # inverted_hex_num = hex_num ^ 0b11111111
            new_value = inverted_hex_num
            # Step 4: Combine the inverted values
            hex_string += str(hex(new_value))[2:]
            string_to_reverse = str('{0:08b}'.format(new_value))
            reversedstring=''.join(reversed(string_to_reverse))
            binary_string += reversedstring

        channel_num = 0
        channel_list = list()

        # 1110 1111 inverse is 0001 0000
        # Step 5: Loop through binary string and add channels
        for c in (binary_string):
            if(channel_num == total_num_channels):
                break
            if(c == '1'):
                # add this channel
                channel_list.append(channel_num)

            channel_num+=1

        channel_list_display_string = ''
        lst = channel_list
        result = str(lst[0])
        end = None
        for index, num in enumerate(lst[1:]):
            if num - 1 == lst[index]:  # the slice shifts the index by 1 for us
                end = str(num)
            else:
                if end:
                    result += '-' + end
                    end = None
                result += ':' + str(num)
        # Catch the last term
        if end:
            result += '-' + str(num)

        channel_list_display_string = result

        return channel_list_display_string

    def convert_to_bitmask(self, input_line='0-128'):

        included_ch_list = (input_line.split(':'))  # 0-10, 15-20 etc
        real_channel_list = list()

        for each_entry in included_ch_list:
            start_channel = int(each_entry.split('-')[0])      # 0

            try:
                end_channel = int(each_entry.split('-')[1])        # 10
            except Exception:
                # in the case of no end channel specified, it means only one channel selected
                end_channel = start_channel
                pass

            for current_channel in range(start_channel, end_channel + 1):
                real_channel_list.append(current_channel)

        count = 0
        channel_mask_byte = 0
        channel_mask_byte_inverted = 0
        eight_multiple = 8
        # convert channel list from right to left
        while(count in range(0, len(real_channel_list))):
            channel_mask_byte = self.set_bit_at_position(real_channel_list[count], channel_mask_byte)
            if(count+1 == len(real_channel_list)):
                break

            if(int(real_channel_list[count+1]) >= eight_multiple):
                eight_multiple += 8

            count += 1

        final_channel = int(real_channel_list[-1])
        mask = 0b1
        channel_mask_byte_inverted = channel_mask_byte

        # increment by 1 to include the last channel
        final_channel += 1
        while(final_channel % 8 != 0):
            # make sure you have an even number of bytes
            final_channel += 1

        # invert every single bit
        """for bit in range(0, final_channel):
            channel_mask_byte_inverted ^= (mask)
            # shift the mask to the left by 1
            mask = mask << 1"""

        value = (hex(channel_mask_byte_inverted)[2:].strip())

        # make sure 17 byte pairs are used
        value = value.zfill(34)
        channel_mask_correct_endian = value

        channel_mask_inverted_hex = bytearray.fromhex(value)
        channel_mask_inverted_hex.reverse()

        channel_mask_correct_endian = channel_mask_inverted_hex.hex()
        return channel_mask_correct_endian, channel_mask_inverted_hex