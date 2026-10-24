import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeSignalSafe {

    public void runJadeSignal() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_JadeSignalSafeSink()).queryJadeSignal(data);
    }
}

class CWE89_P06_V1_JadeSignalSafeSink {
    public void queryJadeSignal(String data) throws SQLException {
        Connection jadeSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSignal");
        Statement jadeSignalStatement = null;
        ResultSet jadeSignalRows = null;
        try {
            jadeSignalStatement = jadeSignalConnection.createStatement();
            jadeSignalRows = jadeSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeSignalRows.getRow());
        } finally {
            if (jadeSignalRows != null) {
                jadeSignalRows.close();
            }
            if (jadeSignalStatement != null) {
                jadeSignalStatement.close();
            }
            jadeSignalConnection.close();
        }
    }
}
