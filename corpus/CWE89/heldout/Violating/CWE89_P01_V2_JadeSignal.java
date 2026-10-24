import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_JadeSignal {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runJadeSignal() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("JADE_SIGNAL_FILTER");
        } else {
            data = null;
        }
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
