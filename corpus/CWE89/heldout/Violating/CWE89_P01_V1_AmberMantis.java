import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AmberMantis {

    public void runAmberMantis() throws SQLException {
        String data;
        data = System.getenv("AMBER_MANTIS_FILTER");
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        Statement amberMantisStatement = null;
        ResultSet amberMantisRows = null;
        try {
            amberMantisStatement = amberMantisConnection.createStatement();
            amberMantisRows = amberMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberMantisRows.getRow());
        } finally {
            if (amberMantisRows != null) {
                amberMantisRows.close();
            }
            if (amberMantisStatement != null) {
                amberMantisStatement.close();
            }
            amberMantisConnection.close();
        }
    }
}
