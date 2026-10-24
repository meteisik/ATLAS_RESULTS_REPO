import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_CobaltOrbitSafe {

    public void runCobaltOrbit() throws SQLException {
        String data;
        data = "foo";
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
}
