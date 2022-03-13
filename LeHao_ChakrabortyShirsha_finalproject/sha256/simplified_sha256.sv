module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);


 
 
enum logic [2:0] {IDLE, READ, READ_WAIT, BLOCK, COMPUTE, WRITE, WRITE_WAIT} state;




logic [19:0][31:0] message;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [511:0] memory_block;
logic [ 7:0] tstep;
logic [15:0][31:0] w;
logic [7:0][31:0] finalHashes;
logic [ 7:0] num_blocks;


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



assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 



function logic [15:0] determine_num_blocks(input logic [31:0] size);
	begin
	
		if ((size >> 4) << 4 == size) begin
			determine_num_blocks = size >> 4;
		// if binary size has at least 4 trailing 0's, and is larger than larger than 15, then 
		// right shift by 4 is num_blocks, because it is a multiple of 16
		// we can detect this by shifting to the right first, then back
		end
		
		else begin
			determine_num_blocks = (size >> 4) + 1;
		//otherwise, message overflows to another block
		//divide by 16 is not an integer result
		end	
		
	end
endfunction




// Message digest intialization constants
parameter int H[0:7] = '{
   32'h6a09e667,32'hbb67ae85,32'h3c6ef372,32'ha54ff53a,32'h510e527f,32'h9b05688c,32'h1f83d9ab,32'h5be0cd19
};




// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h,
											input logic [31:0] w,
                                 input int k);
											
											
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 
	 
	begin

		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + k + w;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	end
	
	
	
endfunction



function logic [31:0] wtnew();


	logic[31:0] s0, s1;
	
	begin
	
		s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1]>>3);
		s1 = rightrotate(w[14],17) ^ rightrotate(w[14],19) ^ (w[14]>>10);
		wtnew = w[0] + s0 + w[9] + s1;
	end
	

endfunction


assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;



function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


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
	 

    BLOCK: begin
	 
	 //j keeps track of which block we are on in message
	 
		if (j == num_blocks) begin
		
		
			finalHashes[0] <= h0;
			finalHashes[1] <= h1;
			finalHashes[2] <= h2;
			finalHashes[3] <= h3;
			finalHashes[4] <= h4;
			finalHashes[5] <= h5;
			finalHashes[6] <= h6;
			finalHashes[7] <= h7;
		
			cur_we <= 1;
			offset <= 0;
			cur_addr <= output_addr;
			cur_write_data <= h0;
			
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
					w[i_] <= message[16+i_];
				end
				
				
				w[4] <= 32'h80000000;
				
				for (int i_ = 5; i_< 15; i_++) begin
					w[i_] <= 0;
				end
				
				w[15] <= 32'd640;
				
				j <= j + 1;
				
				state <= COMPUTE;
			end
			else begin
			
			
				w <= message[15:0];
				j <= j + 1;
				state <= COMPUTE;
				
				
			end
			
		end

    end


    COMPUTE: begin
	 
	 
		if (i < 64) begin
	 

			{a,b,c,d,e,f,g,h} = sha256_op(a,b,c,d,e,f,g,h,w[0],k[i]);
			
			for(int i_=0;i_<15;i_++) w[i_] <= w[i_+1];
			w[15] <= wtnew();	
			
			i <= i + 1;
		
			state <= COMPUTE;
			
		end
		
		else begin
		
			
			h0 <= h0 + a;
			h1 <= h1 + b;
			h2 <= h2 + c;
			h3 <= h3 + d;
			h4 <= h4 + e;
			h5 <= h5 + f;
			h6 <= h6 + g;
			h7 <= h7 + h;	
			
			i <= 0;
			
			
			state <= BLOCK;
		end
			
		
    end


    WRITE: begin
	 
		if (offset == 7) begin
			state <= IDLE;
		end
		else begin
		
	
			offset <= offset + 1;
			cur_write_data <= finalHashes[offset+1];

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
