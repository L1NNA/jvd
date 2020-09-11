import os
import uuid
from shutil import rmtree, unpack_archive
from subprocess import PIPE, STDOUT, Popen
from tempfile import TemporaryDirectory
from zipfile import ZipFile, ZipInfo
import logging as log
import json

from jvd.utils import download_file, home


class ZipFileWithPermissions(ZipFile):
    def _extract_member(self, member, targetpath, pwd):
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        targetpath = super()._extract_member(member, targetpath, pwd)

        attr = member.external_attr >> 16
        if attr != 0:
            os.chmod(targetpath, attr)
        return targetpath


joern_home = os.path.join(
    home, 'joern-cli',
)

bin_exec = os.path.join(
    joern_home, 'joern'
)

script = os.path.join(
    os.path.dirname(__file__), 'src.sc'
)

workspace = os.path.join(
    joern_home, 'workspace'
)


def install_dependencies():
    zip_url = 'https://github.com/ShiftLeftSecurity/joern/releases/download/v1.1.5/joern-cli.zip'
    if not os.path.exists(bin_exec):
        fn = download_file(
            zip_url,
            home,
            progress=True)
        with ZipFileWithPermissions(fn) as zfp:
            zfp.extractall(home)
        if not os.path.exists(bin_exec):
            print('Failed to find the executable for joern after installation.')
    return bin_exec


def extract_pcg(content, file_name='main.cpp'):
    install_dependencies()

    with TemporaryDirectory() as temp_dir:

        temp_prj = uuid.uuid1().hex[:16]
        with open(os.path.join(
                temp_dir, file_name), 'w') as outf:
            outf.write(content)

        cmd = [bin_exec, '--script', script,
               '--params',
               'prjDir={},prjName={}'.format(temp_dir, temp_prj)]
        json_file = os.path.join(
            temp_dir,  temp_prj + '.json'
        )

        p = Popen(cmd, stdout=PIPE, stderr=STDOUT, cwd=joern_home)
        out, err = p.communicate()
        ws = os.path.join(workspace, temp_prj)
        if isinstance(out, bytes):
            out = out.decode('utf-8')
        if os.path.exists(ws):
            rmtree(ws)
        if os.path.exists(json_file):
            with open(json_file) as of:
                return json.load(of), out
        else:
            log.error(
                'No json file generated. Info: {} Err: {}'.format(
                    out, err))
            json_file = None
        return json_file, out


if __name__ == '__main__':
    print('runing testing')
    code = """
# include <stdio.h>
# include <stdlib.h>
# include <string.h>

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
    static av_cold int vdadec_init(AVCodecContext *avctx)\n\n{\n\n    VDADecoderContext *ctx = avctx->priv_data;\n\n    struct vda_context *vda_ctx = &ctx->vda_ctx;\n\n    OSStatus status;\n\n    int ret;\n\n\n\n    ctx->h264_initialized = 0;\n\n\n\n    /* init pix_fmts of codec */\n\n    if (!ff_h264_vda_decoder.pix_fmts) {\n\n        if (kCFCoreFoundationVersionNumber < kCFCoreFoundationVersionNumber10_7)\n\n            ff_h264_vda_decoder.pix_fmts = vda_pixfmts_prior_10_7;\n\n        else\n\n            ff_h264_vda_decoder.pix_fmts = vda_pixfmts;\n\n    }\n\n\n\n    /* init vda */\n\n    memset(vda_ctx, 0, sizeof(struct vda_context));\n\n    vda_ctx->width = avctx->width;\n\n    vda_ctx->height = avctx->height;\n\n    vda_ctx->format = \'avc1\';\n\n    vda_ctx->use_sync_decoding = 1;\n\n    vda_ctx->use_ref_buffer = 1;\n\n    ctx->pix_fmt = avctx->get_format(avctx, avctx->codec->pix_fmts);\n\n    switch (ctx->pix_fmt) {\n\n    case AV_PIX_FMT_UYVY422:\n\n        vda_ctx->cv_pix_fmt_type = \'2vuy\';\n\n        break;\n\n    case AV_PIX_FMT_YUYV422:\n\n        vda_ctx->cv_pix_fmt_type = \'yuvs\';\n\n        break;\n\n    case AV_PIX_FMT_NV12:\n\n        vda_ctx->cv_pix_fmt_type = \'420v\';\n\n        break;\n\n    case AV_PIX_FMT_YUV420P:\n\n        vda_ctx->cv_pix_fmt_type = \'y420\';\n\n        break;\n\n    default:\n\n        av_log(avctx, AV_LOG_ERROR, "Unsupported pixel format: % d\\n", avctx->pix_fmt);\n\n        goto failed;\n\n    }\n\n    status = ff_vda_create_decoder(vda_ctx,\n\n                                   avctx->extradata, avctx->extradata_size);\n\n    if (status != kVDADecoderNoErr) {\n\n        av_log(avctx, AV_LOG_ERROR,\n\n                "Failed to init VDA decoder: % d.\\n", status);\n\n        goto failed;\n\n    }\n\n    avctx->hwaccel_context = vda_ctx;\n\n\n\n    /* changes callback functions */\n\n    avctx->get_format = get_format;\n\n    avctx->get_buffer2 = get_buffer2;\n\n#if FF_API_GET_BUFFER\n\n    // force the old get_buffer to be empty\n\n    avctx->get_buffer = NULL;\n\n#endif\n\n\n\n    /* init H.264 decoder */\n\n    ret = ff_h264_decoder.init(avctx);\n\n    if (ret < 0) {\n\n        av_log(avctx, AV_LOG_ERROR, "Failed to open H.264 decoder.\\n");\n\n        goto failed;\n\n    }\n\n    ctx->h264_initialized = 1;\n\n\n\n    return 0;\n\n\n\nfailed:\n\n    vdadec_close(avctx);\n\n    return -1;\n\n}\n
    """

    obj, logs = extract_pcg(code2)
    print(obj)
    print(logs)
