import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeQuartz {

    public void runJadeQuartz() throws SQLException {
        String data;
        data = System.getenv("JADE_QUARTZ_FILTER");
        (new CWE89_P06_V1_JadeQuartzSink()).queryJadeQuartz(data);
    }
}

class CWE89_P06_V1_JadeQuartzSink {
    public void queryJadeQuartz(String data) throws SQLException {
        Connection jadeQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeQuartz");
        Statement jadeQuartzStatement = null;
        ResultSet jadeQuartzRows = null;
        try {
            jadeQuartzStatement = jadeQuartzConnection.createStatement();
            jadeQuartzRows = jadeQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeQuartzRows.getRow());
        } finally {
            if (jadeQuartzRows != null) {
                jadeQuartzRows.close();
            }
            if (jadeQuartzStatement != null) {
                jadeQuartzStatement.close();
            }
            jadeQuartzConnection.close();
        }
    }
}
