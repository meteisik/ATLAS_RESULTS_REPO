import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_GoldenCipherSafe {

    private void queryGoldenCipher(String data) throws SQLException {
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        Statement goldenCipherStatement = null;
        ResultSet goldenCipherRows = null;
        try {
            goldenCipherStatement = goldenCipherConnection.createStatement();
            goldenCipherRows = goldenCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenCipherRows.getRow());
        } finally {
            if (goldenCipherRows != null) {
                goldenCipherRows.close();
            }
            if (goldenCipherStatement != null) {
                goldenCipherStatement.close();
            }
            goldenCipherConnection.close();
        }
    }

    public void runGoldenCipher() throws SQLException {
        String data;
        data = "foo";
        queryGoldenCipher(data);
    }
}
