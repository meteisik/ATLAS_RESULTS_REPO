import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentOrbitSafe {

    static class Container {
        public String containerOne;
    }

    public void runSilentOrbit() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentOrbitSafeSink()).querySilentOrbit(dataContainer);
    }
}

class CWE89_P09_V1_SilentOrbitSafeSink {
    public void querySilentOrbit(CWE89_P09_V1_SilentOrbitSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        Statement silentOrbitStatement = null;
        ResultSet silentOrbitRows = null;
        try {
            silentOrbitStatement = silentOrbitConnection.createStatement();
            silentOrbitRows = silentOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentOrbitRows.getRow());
        } finally {
            if (silentOrbitRows != null) {
                silentOrbitRows.close();
            }
            if (silentOrbitStatement != null) {
                silentOrbitStatement.close();
            }
            silentOrbitConnection.close();
        }
    }
}
