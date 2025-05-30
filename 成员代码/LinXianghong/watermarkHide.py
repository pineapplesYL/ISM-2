import numpy as np
from PIL import Image
import os
import matplotlib.pyplot as plt
import pywt
from scipy.fftpack import dct, idct
 
# 转换图像为numpy数组
# is_watermark为True时转为灰度图，False时保持RGB格式
def convert_image(image_name, size, is_watermark=False):
    img_path = os.path.join('./pictures', image_name)
    img = Image.open(img_path).resize((size, size), Image.Resampling.LANCZOS)
    if is_watermark:
        # 水印图像转为灰度
        img = img.convert('L')
        image_array = np.array(img, dtype=np.float64)
    else:
        # 载体图像保持RGB
        image_array = np.array(img, dtype=np.float64)
    img_path_save = os.path.join('./dataset', image_name)
    img.save(img_path_save)
    return image_array

# 对图像进行小波变换
def process_dwt(image_array, level=1):
    coeffs = pywt.wavedec2(image_array, 'haar', level=level)
    return coeffs

# 对图像进行分块DCT变换
def apply_dct(image_array):
    size = image_array.shape[0]
    all_subdct = np.empty_like(image_array)
    for i in range(0, size, 8):
        for j in range(0, size, 8):
            subpixels = image_array[i:i + 8, j:j + 8]
            subdct = dct(dct(subpixels.T, norm="ortho").T, norm="ortho")
            all_subdct[i:i + 8, j:j + 8] = subdct
    return all_subdct

# 进行DCT逆变换
def inverse_dct(all_subdct):
    size = all_subdct.shape[0]
    all_subidct = np.empty_like(all_subdct)
    for i in range(0, size, 8):
        for j in range(0, size, 8):
            subidct = idct(idct(all_subdct[i:i + 8, j:j + 8].T, norm="ortho").T, norm="ortho")
            all_subidct[i:i + 8, j:j + 8] = subidct
    return all_subidct

# 在DWT低频系数中嵌入水印
def embed_watermark(watermark_array, dwt_coeffs):
    # 获取低频系数
    LL = dwt_coeffs[0]
    # 对低频系数进行DCT变换
    dct_coeffs = apply_dct(LL)
    # 将水印展平并二值化
    watermark_flat = (watermark_array.ravel() > 128).astype(np.float64)
    ind = 0
    # 在DCT系数中嵌入水印
    for x in range(0, dct_coeffs.shape[0], 8):
        for y in range(0, dct_coeffs.shape[1], 8):
            if ind < watermark_flat.size:
                if(watermark_flat[ind] == 1) :
                    dct_coeffs[x+1, y+1] = dct_coeffs[x+2, y+2] + 80
                elif(watermark_flat[ind] == 0) :
                    dct_coeffs[x+1, y+1] = dct_coeffs[x+2, y+2] - 80
                ind += 1
    # DCT逆变换
    LL_watermarked = inverse_dct(dct_coeffs)

    # 更新DWT系数
    dwt_coeffs_watermarked = list(dwt_coeffs)
    dwt_coeffs_watermarked[0] = LL_watermarked
    return dwt_coeffs_watermarked

# 主函数：完成水印嵌入的整个流程
def embed_watermark_to_image(image_name, watermark_name, output_name):
    # 读取原始图像(RGB)和水印图像(灰度)
    image_array = convert_image(image_name, 4096, False)
    watermark_array = convert_image(watermark_name, 256, True)
    # 分离RGB通道
    r_channel = image_array[:,:,0]
    g_channel = image_array[:,:,1]
    b_channel = image_array[:,:,2]
    # 对R通道进行DWT变换
    dwt_coeffs = process_dwt(r_channel)
    # 嵌入水印
    dwt_coeffs_watermarked = embed_watermark(watermark_array, dwt_coeffs)
    # 小波逆变换得到嵌入水印后的R通道
    r_channel_watermarked = pywt.waverec2(dwt_coeffs_watermarked, 'haar')
    # 处理像素值范围
    r_channel_watermarked = np.clip(r_channel_watermarked, 0, 255)
    # 重新组合RGB通道
    watermarked_image = np.dstack((r_channel_watermarked, g_channel, b_channel)).astype(np.uint8)
    # 保存结果
    img = Image.fromarray(watermarked_image)
    img.save(os.path.join('./result', output_name))
    # 解决中文显示问题
    plt.rcParams['font.sans-serif'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    # 显示结果
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.imshow(image_array.astype(np.uint8))
    plt.title('原始图像')
    plt.axis('off')
    plt.subplot(1, 2, 2)
    plt.imshow(watermarked_image)
    plt.title('嵌入图像')
    plt.axis('off')
    plt.show()
