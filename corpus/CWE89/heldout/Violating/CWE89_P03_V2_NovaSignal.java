import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_NovaSignal {

    private void queryNovaSignal(String data) throws SQLException {
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
        while (true) {
            data = System.getenv("NOVA_SIGNAL_FILTER");
            break;
        }
        queryNovaSignal(data);
    }
}
