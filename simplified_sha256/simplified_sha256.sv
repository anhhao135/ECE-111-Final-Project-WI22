module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, READ_WAIT, BLOCK, COMPUTE, WRITE, WRITE_WAIT} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [63:0][31:0] w;
logic [31:0] message[20];
logic [31:0] wt;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [511:0] memory_block;
logic [ 7:0] tstep;
logic [63:0] messageLength;
logic [(512-64-32*(NUM_OF_WORDS%16)-1)-1:0] zeroPadding;
logic [15:0][31:0] messageBlock;
logic [7:0][31:0] finalHashes;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};




// Message digest intialization constants
parameter int H[0:7] = '{
   32'h6a09e667,32'hbb67ae85,32'h3c6ef372,32'ha54ff53a,32'h510e527f,32'h9b05688c,32'h1f83d9ab,32'h5be0cd19
};




// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h,
											input logic [63:0][31:0] w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w[t];
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction




function logic [63:0][31:0] wordExpansion(input logic [16:0][31:0] messageBlock);

	logic [31:0] s1, s0; //internal signals

	begin

		for (int t = 0; t < 64; t++) begin
			if (t < 16) begin
				wordExpansion[t] = messageBlock[t];
			end
			
			else begin
			
				s0 = rightrotate(wordExpansion[t-15], 7) ^ rightrotate(wordExpansion[t-15], 18) ^ (wordExpansion[t-15] >> 3);
				s1 = rightrotate(wordExpansion[t-2], 17) ^ rightrotate(wordExpansion[t-2], 19) ^ (wordExpansion[t-2] >> 10);
				wordExpansion[t] = wordExpansion[t-16] + s0 + wordExpansion[t-7] + s1;
				
			end
		end
	end
	
endfunction





// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
		 
			h0 <= H[0];
			h1 <= H[1];
			h2 <= H[2];
			h3 <= H[3];
			h4 <= H[4];
			h5 <= H[5];
			h6 <= H[6];
			h7 <= H[7];		
			
			
			
			cur_we <= 0;
			cur_addr <= message_addr;
			offset <= 0;
			
			i <= 0;
			j <= 0;
			
			messageLength <= NUM_OF_WORDS * 32;
			
			zeroPadding <= 0;
			
			wt <= 0;
			
			num_blocks = 2;
			
			state <= READ_WAIT;
			
       end
    end
	 
	 
	 READ: begin
	 
		message[offset] <= mem_read_data;
		
		if (offset == NUM_OF_WORDS - 1) begin
			
			state <= BLOCK;

		end
		else begin
		
			offset = offset + 1;
			state <= READ_WAIT;
		end
		
	 end
	 
	 READ_WAIT: begin
	 
		state <= READ;
		
	 end
	 

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK: begin
	 
	 //j keeps track of which block we are on in message
	 
		if (j == num_blocks) begin
		
		
			finalHashes[0] = h0;
			finalHashes[1] = h1;
			finalHashes[2] = h2;
			finalHashes[3] = h3;
			finalHashes[4] = h4;
			finalHashes[5] = h5;
			finalHashes[6] = h6;
			finalHashes[7] = h7;
		
			cur_we <= 1;
			offset <= 0;
			cur_addr <= output_addr;
			cur_write_data <= finalHashes[0];
			
			state <= WRITE_WAIT;
		end
		
		else begin
		
			a <= h0;
			b <= h1;
			c <= h2;
			d <= h3;
			e <= h4;
			f <= h5;
			g <= h6;
			h <= h7;	
		
		
			if (j == num_blocks - 1) begin //check if this is the last block, because if so it will need padding and msg length
				
				for (int i_ = 0; i_< 4; i_++) begin
					messageBlock[i_] = message[16*j+i_];
				end
				
				
				messageBlock[4] = 32'h80000000;
				
				for (int i_ = 5; i_< 15; i_++) begin
					messageBlock[i_] = 0;
				end
				
				messageBlock[15] = 32'd640;
				
				j <= j + 1;
				state <= COMPUTE;
			end
			else begin
			
				for (int i_ = 0; i_< 16; i_++) begin
					messageBlock[i_] = message[16*j+i_];
				end
				
				j <= j + 1;
				state <= COMPUTE;
			end
			
		end
	 
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation


    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	 
		w = wordExpansion(messageBlock);
		
		
		for (i = 0; i < 64; i++) begin
			{a,b,c,d,e,f,g,h} = sha256_op(a,b,c,d,e,f,g,h,w,i);
		end
		
		h0 <= h0 + a;
		h1 <= h1 + b;
		h2 <= h2 + c;
		h3 <= h3 + d;
		h4 <= h4 + e;
		h5 <= h5 + f;
		h6 <= h6 + g;
		h7 <= h7 + h;	
		
		
		state <= BLOCK;
		
		
    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
	 
		if (offset == 7) begin
			state <= IDLE;
		end
		else begin
		
	
			offset = offset + 1;
			cur_write_data = finalHashes[offset];

			state <= WRITE_WAIT;
		end
		

    end
	 
	 WRITE_WAIT: begin
		
		state <= WRITE;
		
	 end
	 
	 
	 
   endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
