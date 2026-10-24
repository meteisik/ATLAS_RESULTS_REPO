import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CobaltOrbit {

    private void queryCobaltOrbit(String data) throws SQLException {
        Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
        Statement cobaltOrbitStatement = null;
        ResultSet cobaltOrbitRows = null;
        try {
            cobaltOrbitStatement = cobaltOrbitConnection.createStatement();
            cobaltOrbitRows = cobaltOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltOrbitRows.getRow());
        } finally {
            if (cobaltOrbitRows != null) {
                cobaltOrbitRows.close();
            }
            if (cobaltOrbitStatement != null) {
                cobaltOrbitStatement.close();
            }
            cobaltOrbitConnection.close();
        }
    }

    public void runCobaltOrbit() throws SQLException {
        String data;
        data = System.getenv("COBALT_ORBIT_FILTER");
        queryCobaltOrbit(data);
    }
}
