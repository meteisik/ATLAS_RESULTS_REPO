import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeSignalSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runJadeSignal() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
