import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberMantis {
    private static boolean privateTrue = true;

    public static String data;

    public void runAmberMantis() throws SQLException {
        if (privateTrue) {
            data = System.getenv("AMBER_MANTIS_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberMantisSink()).queryAmberMantis();
    }
}

class CWE89_P10_V2_AmberMantisSink {
    public void queryAmberMantis() throws SQLException {
        String data = CWE89_P10_V2_AmberMantis.data;
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
