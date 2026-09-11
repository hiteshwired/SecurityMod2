"""
Helper script to generate a sample 24-bit uncompressed BMP image with high-contrast
geometric shapes. This visually demonstrates the ECB pattern-leakage vulnerability
versus CBC mode diffusion.
"""

import struct


def create_sample_bmp(filename: str = "sample.bmp", width: int = 256, height: int = 256):
    """
    Creates a standard 24-bit uncompressed BMP image (54-byte header).
    The image contains high-contrast shapes (circles, squares, cross) on a solid background
    to clearly demonstrate how ECB mode leaks plaintext patterns.
    """
    # Row size in BMP must be padded to a multiple of 4 bytes
    row_size = (width * 3 + 3) & ~3
    image_size = row_size * height
    file_size = 54 + image_size
    
    # 14-byte BMP Header
    # 'BM' (2 bytes), File Size (4 bytes), Reserved (4 bytes), Data Offset (4 bytes = 54)
    bmp_header = struct.pack(
        "<2sIHHI",
        b"BM",
        file_size,
        0,
        0,
        54
    )
    
    # 40-byte DIB Header (BITMAPINFOHEADER)
    # Header size (40), Width, Height, Planes (1), BitsPerPixel (24), Compression (0 = BI_RGB),
    # Image size, X pixels/meter, Y pixels/meter, Colors in palette, Important colors
    dib_header = struct.pack(
        "<IIIHHIIIIII",
        40,
        width,
        height,
        1,
        24,
        0,
        image_size,
        2835,
        2835,
        0,
        0
    )
    
    # Pixel data (BGR format, bottom-to-top)
    pixel_data = bytearray()
    
    # Define colors (BGR)
    bg_color = (255, 255, 255)       # White
    fg_color = (0, 0, 180)           # Dark Red
    accent_color = (180, 0, 0)       # Dark Blue
    center_color = (0, 150, 0)       # Green
    
    center_x = width // 2
    center_y = height // 2
    
    for y in range(height):
        row = bytearray()
        for x in range(width):
            dx = x - center_x
            dy = y - center_y
            dist_sq = dx * dx + dy * dy
            
            # Central circular logo
            if dist_sq < 30 * 30:
                color = center_color
            elif 45 * 45 < dist_sq < 75 * 75:
                color = fg_color
            # Square boundary
            elif (abs(dx) < 95 and abs(dy) < 95) and not (abs(dx) < 85 and abs(dy) < 85):
                color = accent_color
            # Cross lines
            elif abs(dx) < 4 and abs(dy) < 110:
                color = fg_color
            elif abs(dy) < 4 and abs(dx) < 110:
                color = fg_color
            else:
                color = bg_color
                
            row.extend([color[0], color[1], color[2]])
            
        # Add padding bytes to make row length multiple of 4
        pad_bytes = row_size - (width * 3)
        row.extend([0] * pad_bytes)
        pixel_data.extend(row)
        
    with open(filename, "wb") as f:
        f.write(bmp_header + dib_header + pixel_data)
        
    print(f"[CREATED] Sample BMP image saved as '{filename}' ({width}x{height}, 24bpp, 54-byte header).")


if __name__ == "__main__":
    create_sample_bmp("sample.bmp")
