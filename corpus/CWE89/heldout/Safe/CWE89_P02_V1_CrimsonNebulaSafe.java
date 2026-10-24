import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonNebulaSafe {

    public void runCrimsonNebula() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
            Statement crimsonNebulaStatement = null;
            ResultSet crimsonNebulaRows = null;
            try {
                crimsonNebulaStatement = crimsonNebulaConnection.createStatement();
                crimsonNebulaRows = crimsonNebulaStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(crimsonNebulaRows.getRow());
            } finally {
                if (crimsonNebulaRows != null) {
                    crimsonNebulaRows.close();
                }
                if (crimsonNebulaStatement != null) {
                    crimsonNebulaStatement.close();
                }
                crimsonNebulaConnection.close();
            }
        }
    }
}
