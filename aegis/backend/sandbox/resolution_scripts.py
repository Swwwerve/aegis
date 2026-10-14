"""Trusted inspection helpers copied into an untrusted, network-disabled workspace."""

PYTHON_METADATA = r"""
import email,json,pathlib,sys
from build import ProjectBuilder
from importlib.metadata import distributions
from packaging.markers import default_environment
output=pathlib.Path(sys.argv[1])
output.mkdir(parents=True,exist_ok=True)
metadata=pathlib.Path(ProjectBuilder('.').metadata_path(str(output))).resolve()
if not metadata.is_relative_to(output.resolve()):
    raise ValueError('Build backend returned a metadata path outside the report directory')
message=email.message_from_string((metadata/'METADATA').read_text())
installed={d.metadata['Name'].lower().replace('_','-'): {'version':d.version,'requires':d.requires or []} for d in distributions() if d.metadata['Name']}
print('AEGIS_JSON:'+json.dumps({'name':message['Name'],'requires':message.get_all('Requires-Dist') or [],'installed':installed,'environment':default_environment()}))
"""

NODE_TREE = r"""
const fs=require('fs'),path=require('path'),{createRequire}=require('module');
const dependencies=[],edges=[],errors=[],seen=new Set();
function locate(req,name) {
  try { return req.resolve(name+'/package.json'); } catch(error) {
    let directory=path.dirname(req.resolve(name));
    while(directory!==path.dirname(directory)) {
      const manifest=path.join(directory,'package.json');
      if(fs.existsSync(manifest)) return manifest;
      directory=path.dirname(directory);
    }
    throw error;
  }
}
function visit(manifest,isRoot=false) {
  manifest=fs.realpathSync(manifest);
  if(seen.has(manifest)) return;
  if(seen.size>=10000) throw new Error('Node dependency traversal limit');
  seen.add(manifest);
  const data=JSON.parse(fs.readFileSync(manifest,'utf8'));
  const parent=(data.name||'root')+(isRoot?'':'@'+data.version);
  const req=createRequire(manifest);
  const requested={...data.dependencies,...data.optionalDependencies,...data.peerDependencies,...(isRoot?data.devDependencies:{})};
  for(const name of Object.keys(requested)) {
    try {
      const child=locate(req,name),metadata=JSON.parse(fs.readFileSync(child,'utf8'));
      if(!metadata.version) throw new Error('Missing package version');
      const scope=isRoot&&data.devDependencies&&name in data.devDependencies?'dev':'runtime';
      dependencies.push({name:metadata.name||name,version:metadata.version,scope});
      edges.push({parent,child:(metadata.name||name)+'@'+metadata.version,scope});
      visit(child);
    } catch(error) {
      const optional=data.optionalDependencies&&name in data.optionalDependencies || data.peerDependenciesMeta&&data.peerDependenciesMeta[name]&&data.peerDependenciesMeta[name].optional;
      if(!optional) errors.push('Unresolved dependency '+name+' required by '+parent);
    }
  }
}
visit(path.join(process.cwd(),'package.json'),true);
console.log('AEGIS_JSON:'+JSON.stringify({dependencies,edges,errors}));
"""

YARN_PNP = r"""
const fs=require('fs'),path=require('path');
let pnp; try { pnp=require('pnpapi'); } catch(error) { pnp=null; }
if(!pnp) {
  process.stdout.write(require('child_process').execFileSync('npm',['ls','--all','--json'],{encoding:'utf8'}));
} else {
  const dependencies=[],edges=[],errors=[],info=new Map();
  const key=(loc)=>JSON.stringify(loc);
  for(const loc of pnp.getAllLocators()) {
    const data=pnp.getPackageInformation(loc);
    try {
      const metadata=JSON.parse(fs.readFileSync(path.join(data.packageLocation,'package.json'),'utf8'));
      const identity=loc.reference.startsWith('workspace:')?loc.name:loc.name+'@'+metadata.version;
      info.set(key(loc),{identity,data,metadata});
      if(!loc.reference.startsWith('workspace:')) dependencies.push({name:metadata.name||loc.name,version:metadata.version,scope:'installed'});
    } catch(error) { errors.push('Unable to inspect package '+loc.name); }
  }
  for(const item of info.values()) {
    for(const [name,reference] of item.data.packageDependencies) {
      if(reference===null) continue;
      const loc=pnp.getLocator(name,reference),target=info.get(key(loc));
      if(target) edges.push({parent:item.identity,child:target.identity});
      else errors.push('Unresolved package '+name);
    }
  }
  console.log('AEGIS_JSON:'+JSON.stringify({dependencies,edges,errors}));
}
"""

GRADLE_INSPECT = r"""
import groovy.json.JsonOutput
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.artifacts.result.UnresolvedDependencyResult
gradle.projectsEvaluated {
    rootProject.tasks.register('aegisInspectDependencies') {
        doLast {
            def rows = []; def edges = []; def errors = []
            rootProject.allprojects.each { p ->
                p.configurations.findAll { it.canBeResolved }.each { c ->
                    try {
                        def result = c.incoming.resolutionResult
                        result.allComponents.each { component ->
                            def id = component.moduleVersion
                            if (id != null && component.id instanceof org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
                                rows << [name: "${id.group}:${id.name}".toString(), version:id.version, scope:"${p.path}:${c.name}".toString()]
                            }
                        }
                        result.allDependencies.each { d ->
                            if (d instanceof ResolvedDependencyResult) {
                                edges << [parent:d.from.id.displayName, child:d.selected.id.displayName, scope:"${p.path}:${c.name}".toString()]
                            } else if (d instanceof UnresolvedDependencyResult) {
                                errors << "${p.path}:${c.name}: ${d.attempted.displayName}: ${d.failure.message}".toString()
                            }
                        }
                    } catch (Exception e) { errors << "${p.path}:${c.name}: ${e.message}".toString() }
                }
            }
            println('AEGIS_JSON:' + JsonOutput.toJson([dependencies:rows.unique(),edges:edges.unique(),errors:errors.unique()]))
        }
    }
}
"""
