import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_NovaSignalSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String novaSignalData;

    private void queryNovaSignal() throws SQLException {
        String data = novaSignalData;
        Connection novaSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSignal");
        Statement novaSignalStatement = null;
        ResultSet novaSignalRows = null;
        try {
            novaSignalStatement = novaSignalConnection.createStatement();
            novaSignalRows = novaSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaSignalRows.getRow());
        } finally {
            if (novaSignalRows != null) {
                novaSignalRows.close();
            }
            if (novaSignalStatement != null) {
                novaSignalStatement.close();
            }
            novaSignalConnection.close();
        }
    }

    public void runNovaSignal() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        novaSignalData = data;
        queryNovaSignal();
    }
}
