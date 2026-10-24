import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CrimsonOrbit {

    private void queryCrimsonOrbit(String data) throws SQLException {
        Connection crimsonOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonOrbit");
        Statement crimsonOrbitStatement = null;
        ResultSet crimsonOrbitRows = null;
        try {
            crimsonOrbitStatement = crimsonOrbitConnection.createStatement();
            crimsonOrbitRows = crimsonOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonOrbitRows.getRow());
        } finally {
            if (crimsonOrbitRows != null) {
                crimsonOrbitRows.close();
            }
            if (crimsonOrbitStatement != null) {
                crimsonOrbitStatement.close();
            }
            crimsonOrbitConnection.close();
        }
    }

    public void runCrimsonOrbit() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_ORBIT_FILTER");
        queryCrimsonOrbit(data);
    }
}
