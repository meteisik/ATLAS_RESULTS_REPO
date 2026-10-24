import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VividSignalSafe {

    static class Container {
        public String containerOne;
    }

    public void runVividSignal() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VividSignalSafeSink()).queryVividSignal(dataContainer);
    }
}

class CWE89_P09_V2_VividSignalSafeSink {
    public void queryVividSignal(CWE89_P09_V2_VividSignalSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection vividSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSignal");
        Statement vividSignalStatement = null;
        ResultSet vividSignalRows = null;
        try {
            vividSignalStatement = vividSignalConnection.createStatement();
            vividSignalRows = vividSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSignalRows.getRow());
        } finally {
            if (vividSignalRows != null) {
                vividSignalRows.close();
            }
            if (vividSignalStatement != null) {
                vividSignalStatement.close();
            }
            vividSignalConnection.close();
        }
    }
}
