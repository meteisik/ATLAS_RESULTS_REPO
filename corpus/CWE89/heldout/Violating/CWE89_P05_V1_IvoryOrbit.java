import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_IvoryOrbit {

    private String ivoryOrbitData;

    private void queryIvoryOrbit() throws SQLException {
        String data = ivoryOrbitData;
        Connection ivoryOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryOrbit");
        Statement ivoryOrbitStatement = null;
        ResultSet ivoryOrbitRows = null;
        try {
            ivoryOrbitStatement = ivoryOrbitConnection.createStatement();
            ivoryOrbitRows = ivoryOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryOrbitRows.getRow());
        } finally {
            if (ivoryOrbitRows != null) {
                ivoryOrbitRows.close();
            }
            if (ivoryOrbitStatement != null) {
                ivoryOrbitStatement.close();
            }
            ivoryOrbitConnection.close();
        }
    }

    public void runIvoryOrbit() throws SQLException {
        String data;
        data = System.getenv("IVORY_ORBIT_FILTER");
        ivoryOrbitData = data;
        queryIvoryOrbit();
    }
}
