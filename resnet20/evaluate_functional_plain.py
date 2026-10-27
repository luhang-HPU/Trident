from pathlib import Path
import numpy as np
import torch
import torch.nn.functional as F
import json
import argparse
parser=argparse.ArgumentParser(description='Fixed-configuration plaintext diagnostic; never calibrates on test data.')
parser.add_argument('--count',type=int,default=100)
parser.add_argument('--degree',type=int,choices=[0,15,31],default=0)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
if args.count < 1 or args.count > 1000: parser.error('bundled set supports 1..1000 images')
root=Path(__file__).resolve().parent
weights=root/'pretrained_parameters/resnet20_new'
torch.set_num_threads(4)
count=args.count
images=np.fromfile(root/'testFile/test_values.txt',sep=' ',count=count*3072).reshape(-1,3,32,32)
labels=np.fromfile(root/'testFile/test_label.txt',sep=' ',count=count).astype(int)
def load(name):
 return torch.from_numpy(np.fromfile(weights/(name+'.txt'),sep=' '))
def convbn(x,conv,bn,co,stride=1):
 w=load(conv+'_weight').reshape(co,x.shape[1],3,3)
 gain=load(bn+'_weight')/torch.sqrt(load(bn+'_running_var')+1e-5)
 offset=(load(bn+'_bias')-load(bn+'_running_mean')*gain)/40
 return F.conv2d(x,w,stride=stride,padding=1)*gain[None,:,None,None]+offset[None,:,None,None]
stats=[]
fit=None
if args.degree:
 rows=(root/'functional_params'/f'relu_d{args.degree}.txt').read_text().splitlines()
 phase,degree,error=rows[1].split()
 fit=(float(phase),float(rows[2]),np.array([list(map(float,row.split())) for row in rows[3:]]))
def activate(x,name):
 stats.append({'site':name,'min':float(x.min()),'max':float(x.max()),'outside_unit':int((x.abs()>1).sum())})
 if fit is None: return x.relu()
 phase,c0,coeff=fit
 theta=(2*np.pi*phase)*x
 # Real recurrence retains both sine and cosine components, no clipping.
 cos1,sin1=torch.cos(theta),torch.sin(theta)
 cosk,sink=cos1,sin1
 out=torch.full_like(x,c0)
 for a,b in coeff:
  out.add_(cosk,alpha=float(a)).add_(sink,alpha=float(b))
  cosk,sink=cosk*cos1-sink*sin1,sink*cos1+cosk*sin1
 return out
with torch.no_grad():
 x=torch.from_numpy(images)/40
 x=activate(convbn(x,'conv1','bn1',16),'stem')
 for stage in range(1,4):
  co=2**(stage+3)
  for block in range(3):
   prefix=f'layer{stage}_{block}'
   stride=2 if stage>1 and block==0 else 1
   shortcut=x
   x=activate(convbn(x,prefix+'_conv1',prefix+'_bn1',co,stride),prefix+'.conv1')
   x=convbn(x,prefix+'_conv2',prefix+'_bn2',co)
   if stride==2:
    shortcut=F.pad(shortcut[:,:,::2,::2],(0,0,0,0,shortcut.shape[1]//2,shortcut.shape[1]//2))
   x=activate(x+shortcut,prefix+'.add')
 logits=F.linear(x.mean((2,3))*40,load('linear_weight').reshape(10,64),load('linear_bias'))
 result={'scope':'bundled test subset, fixed b=1, float64; diagnostic, no calibration', 'degree':args.degree,'images':len(images),'correct':int((logits.argmax(1).numpy()==labels).sum()),'sites':stats}
 print(json.dumps(result,indent=2))
 args.output.write_text(json.dumps(result,indent=2))
