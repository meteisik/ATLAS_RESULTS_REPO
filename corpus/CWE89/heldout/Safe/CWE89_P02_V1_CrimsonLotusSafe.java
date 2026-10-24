import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonLotusSafe {

    public void runCrimsonLotus() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection crimsonLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLotus");
            Statement crimsonLotusStatement = null;
            ResultSet crimsonLotusRows = null;
            try {
                crimsonLotusStatement = crimsonLotusConnection.createStatement();
                crimsonLotusRows = crimsonLotusStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(crimsonLotusRows.getRow());
            } finally {
                if (crimsonLotusRows != null) {
                    crimsonLotusRows.close();
                }
                if (crimsonLotusStatement != null) {
                    crimsonLotusStatement.close();
                }
                crimsonLotusConnection.close();
            }
        }
    }
}
