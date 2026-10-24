import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_CrimsonOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runCrimsonOrbit() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_ORBIT_FILTER");
        } else {
            data = null;
        }
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
