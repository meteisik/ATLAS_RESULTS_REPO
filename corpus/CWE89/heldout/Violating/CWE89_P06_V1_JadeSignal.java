import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadeSignal {

    public void runJadeSignal() throws SQLException {
        String data;
        data = System.getenv("JADE_SIGNAL_FILTER");
        (new CWE89_P06_V1_JadeSignalSink()).queryJadeSignal(data);
    }
}

class CWE89_P06_V1_JadeSignalSink {
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
