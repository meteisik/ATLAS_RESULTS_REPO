import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_NovaSignalSafe {

    public void runNovaSignal() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_NovaSignalSafeSink()).queryNovaSignal(data);
    }
}

class CWE89_P06_V1_NovaSignalSafeSink {
    public void queryNovaSignal(String data) throws SQLException {
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
}
