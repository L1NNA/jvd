/* pdg.sc

   This script returns a complete PDG for functions matching a regex, or the whole CPG if no regex is specified. The PDG
   is represented as two lists, one for the edges and another for the vertices.

   The first list contains all of the edges in the PDG. The first entry in each tuple contains the ID of the incoming
   vertex. The second entry in the tuple contains the ID of the outgoing vertex.

   The second list contains all the vertices in the PDG. The first entry in each tuple contains the ID of the vertex
   and the second entry contains the code stored in the vertex.
*/

import io.shiftleft.codepropertygraph.generated.EdgeTypes
import overflowdb._
import overflowdb.traversal._
import scala.collection.mutable
import java.io.PrintWriter

import scala.collection.mutable.ListBuffer

object JsonConverter {
  def toJson(o: Any) : String = {
    var json = new ListBuffer[String]()
    o match {
      case m: Map[_,_] => {
        for ( (k,v) <- m ) {
          var key = escape(k.asInstanceOf[String])
          v match {
            case a: Map[_,_] => json += "\"" + key + "\":" + toJson(a)
            case a: List[_] => json += "\"" + key + "\":" + toJson(a)
            case a: Int => json += "\"" + key + "\":" + a
            case a: Long => json += "\"" + key + "\":" + a
            case a: Boolean => json += "\"" + key + "\":" + a
            case a: String => json += "\"" + key + "\":\"" + escape(a) + "\""
            case _ => ;
          }
        }
      }
      case m: List[_] => {
        var list = new ListBuffer[String]()
        for ( el <- m ) {
          el match {
            case a: Map[_,_] => list += toJson(a)
            case a: List[_] => list += toJson(a)
            case a: Int => list += a.toString()
            case a: Long => list += a.toString()
            case a: Boolean => list += a.toString()
            case a: String => list += "\"" + escape(a) + "\""
            case _ => ;
          }
        }
        return "[" + list.mkString(",") + "]"
      }
      case _ => ;
    }
    return "{" + json.mkString(",") + "}"
  }

  private def escape(s: String) : String = {
    return s.replaceAll("\"" , "\\\\\"");
  }
}


type EdgeEntry = (Long, Long)
type VertexEntry = (Long, String)
type Pdg = (Option[String], List[EdgeEntry], List[VertexEntry])


private def pdgFromEdges(edges: Traversal[OdbEdge]): (List[EdgeEntry], List[VertexEntry]) = {
  val filteredEdges = edges.hasLabel(EdgeTypes.REACHING_DEF, EdgeTypes.CDG).dedup.l

  val (edgeResult, vertexResult) =
    filteredEdges.foldLeft((mutable.Set.empty[EdgeEntry], mutable.Set.empty[VertexEntry])) {
      case ((edgeList, vertexList), edge) =>
        val edgeEntry = (edge.inNode.id, edge.outNode.id)
        val inVertexEntry = (edge.inNode.id, edge.inNode.propertyOption(NodeKeysOdb.CODE).getOrElse(""))
        val outVertexEntry = (edge.outNode.id, edge.outNode.propertyOption(NodeKeysOdb.CODE).getOrElse(""))

        (edgeList += edgeEntry, vertexList ++= Set(inVertexEntry, outVertexEntry))
    }

  (edgeResult.toList, vertexResult.toList)
}

@main def main(prjDir: String, prjName: String): String = {
  importCode(inputPath=prjDir, projectName=prjName)
    val (edgeEntries, vertexEntries) = pdgFromEdges(cpg.graph.E())
    val edges = edgeEntries.map(x=>List(x._1, x._2))
    val vertices = vertexEntries.map(x=>List(x._1, x._2))
    val m = Map("edges"->edges, "vertices"->vertices)
    val js = JsonConverter.toJson(m)
    new PrintWriter(prjDir + "/" + prjName + ".json") { write(js); close }
    return js
}
