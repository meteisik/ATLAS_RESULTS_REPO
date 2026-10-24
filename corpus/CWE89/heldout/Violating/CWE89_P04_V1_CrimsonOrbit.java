import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_CrimsonOrbit {

    private String loadCrimsonOrbit() {
        String data;
        data = System.getenv("CRIMSON_ORBIT_FILTER");
        return data;
    }

    public void runCrimsonOrbit() throws SQLException {
        String data = loadCrimsonOrbit();
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
}
