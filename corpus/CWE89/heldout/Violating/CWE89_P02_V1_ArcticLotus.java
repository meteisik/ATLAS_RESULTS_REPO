import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_ArcticLotus {

    public void runArcticLotus() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_LOTUS_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
            Statement arcticLotusStatement = null;
            ResultSet arcticLotusRows = null;
            try {
                arcticLotusStatement = arcticLotusConnection.createStatement();
                arcticLotusRows = arcticLotusStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(arcticLotusRows.getRow());
            } finally {
                if (arcticLotusRows != null) {
                    arcticLotusRows.close();
                }
                if (arcticLotusStatement != null) {
                    arcticLotusStatement.close();
                }
                arcticLotusConnection.close();
            }
        }
    }
}
