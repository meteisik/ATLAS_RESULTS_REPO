import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonOrbitSafe {

    public void runCrimsonOrbit() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
