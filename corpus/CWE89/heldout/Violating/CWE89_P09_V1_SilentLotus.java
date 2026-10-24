import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentLotus {

    static class Container {
        public String containerOne;
    }

    public void runSilentLotus() throws SQLException {
        String data;
        data = System.getenv("SILENT_LOTUS_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentLotusSink()).querySilentLotus(dataContainer);
    }
}

class CWE89_P09_V1_SilentLotusSink {
    public void querySilentLotus(CWE89_P09_V1_SilentLotus.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection silentLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLotus");
        Statement silentLotusStatement = null;
        ResultSet silentLotusRows = null;
        try {
            silentLotusStatement = silentLotusConnection.createStatement();
            silentLotusRows = silentLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentLotusRows.getRow());
        } finally {
            if (silentLotusRows != null) {
                silentLotusRows.close();
            }
            if (silentLotusStatement != null) {
                silentLotusStatement.close();
            }
            silentLotusConnection.close();
        }
    }
}
