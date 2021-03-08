from jvd.src import SourceFragment


def test_cpp_tree():
    code = """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "42") == 0) {
        fprintf(stderr, "It depends!\n");
        exit(42);
    }
    printf("What is the meaning of life?\n");
    exit(0);
    }
    """

    code2 = """
    static av_cold int vdadec_init(AVCodecContext *avctx)
{
    VDADecoderContext *ctx = avctx->priv_data;
    struct vda_context *vda_ctx = &ctx->vda_ctx;
    OSStatus status;
    int ret;

    ctx->h264_initialized = 0;

    /* init pix_fmts of codec */
    if (!ff_h264_vda_decoder.pix_fmts) {
        if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber10_7)
            ff_h264_vda_decoder.pix_fmts = vda_pixfmts_prior_10_7;
        else
            ff_h264_vda_decoder.pix_fmts = vda_pixfmts;
    }

    /* init vda */
    memset(vda_ctx, 0, sizeof(struct vda_context));
    vda_ctx->width = avctx->width;
    vda_ctx->height = avctx->height;
    vda_ctx->format = \'avc1\';
    vda_ctx->use_sync_decoding = 1;
    vda_ctx->use_ref_buffer = 1;
    ctx->pix_fmt = avctx->get_format(avctx, avctx->codec->pix_fmts);
    switch (ctx->pix_fmt) {
    case AV_PIX_FMT_UYVY422:
        vda_ctx->cv_pix_fmt_type = \'2vuy\';
        break;
    case AV_PIX_FMT_YUYV422:
        vda_ctx->cv_pix_fmt_type = \'yuvs\';
        break;
    case AV_PIX_FMT_NV12:
        vda_ctx->cv_pix_fmt_type = \'420v\';
        break;
    case AV_PIX_FMT_YUV420P:
        vda_ctx->cv_pix_fmt_type = \'y420\';
        break;
    default:
        av_log(avctx, AV_LOG_ERROR, "Unsupported pixel format: % d\\n", avctx->pix_fmt);
        goto failed;
    }
    status = ff_vda_create_decoder(vda_ctx,
                                   avctx->extradata, avctx->extradata_size);
    if (status != kVDADecoderNoErr) {
        av_log(avctx, AV_LOG_ERROR,
                "Failed to init VDA decoder: % d.\\n", status);
        goto failed;
    }
    avctx->hwaccel_context = vda_ctx;

    /* changes callback functions */
    avctx->get_format = get_format;
    avctx->get_buffer2 = get_buffer2;
#if FF_API_GET_BUFFER
    // force the old get_buffer to be empty
    avctx->get_buffer = NULL;
#endif

    /* init H.264 decoder */
    ret = ff_h264_decoder.init(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to open H.264 decoder.\\n");
        goto failed;
    }
    ctx->h264_initialized = 1;

    return 0;

failed:
    vdadec_close(avctx);
    return -1;
}\n
    """

    sf = SourceFragment(code)
    obj = sf.gen_graph()
    assert sf.lang in ('c', 'cpp')
    assert obj is not None
    assert len(sf.tokens) > 10
    assert len(obj.nodes) > 5
    assert len(obj.edges) > 5

    sf = SourceFragment(code2, lang='cpp')
    obj = sf.gen_graph()
    assert sf.lang in ('c', 'cpp')
    assert obj is not None
    assert len(sf.tokens) > 10
    assert len(obj.nodes) > 5


def test_python_tree():
    with open(__file__) as rf:
        code = rf.read()

    sf = SourceFragment(code)
    obj = sf.gen_graph()
    assert sf.lang in ('python', 'python2', 'python3')
    assert obj is not None
    assert len(sf.tokens) > 10
    assert len(obj.nodes) > 5
    assert len(obj.edges) > 5


def test_java_tree():
    code = """
//sample code to write 100 random ints to a file, 1 per line
import java.io.PrintStream;
import java.io.IOException;
import java.io.File;

import java.util.Random;

public class WriteToFile
{	public static void main(String[] args)
	{	try
		{	PrintStream writer = new PrintStream( new File("randInts.txt"));
			Random r = new Random();
			final int LIMIT = 100;

			for(int i = 0; i < LIMIT; i++)
			{	writer.println( r.nextInt() );
			}
			writer.close();
		}
		catch(IOException e)
		{	System.out.println("An error occured while trying to write to the file");
		}
	}
}
    """

    sf = SourceFragment(code, 'java')
    obj = sf.gen_graph()
    assert sf.lang in ('java')
    assert obj is not None
    assert len(sf.tokens) > 10
    assert len(obj.nodes) > 5
    assert len(obj.edges) > 5
