import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_SaffronCipherSafe {
    private static int privateFive = 5;

    private String saffronCipherData;

    private void querySaffronCipher() throws SQLException {
        String data = saffronCipherData;
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        Statement saffronCipherStatement = null;
        ResultSet saffronCipherRows = null;
        try {
            saffronCipherStatement = saffronCipherConnection.createStatement();
            saffronCipherRows = saffronCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronCipherRows.getRow());
        } finally {
            if (saffronCipherRows != null) {
                saffronCipherRows.close();
            }
            if (saffronCipherStatement != null) {
                saffronCipherStatement.close();
            }
            saffronCipherConnection.close();
        }
    }

    public void runSaffronCipher() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        saffronCipherData = data;
        querySaffronCipher();
    }
}
