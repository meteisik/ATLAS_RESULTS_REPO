import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_JadeSignalSafe {

    private String jadeSignalData;

    private void queryJadeSignal() throws SQLException {
        String data = jadeSignalData;
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

    public void runJadeSignal() throws SQLException {
        String data;
        data = "foo";
        jadeSignalData = data;
        queryJadeSignal();
    }
}
