import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeQuartzSafe {

    public void runJadeQuartz() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_JadeQuartzSafeSink()).queryJadeQuartz(data);
    }
}

class CWE89_P06_V1_JadeQuartzSafeSink {
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
