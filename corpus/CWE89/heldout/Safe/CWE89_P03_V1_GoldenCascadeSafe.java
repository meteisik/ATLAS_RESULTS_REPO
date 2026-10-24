import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_GoldenCascadeSafe {

    private void queryGoldenCascade(String data) throws SQLException {
        Connection goldenCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCascade");
        Statement goldenCascadeStatement = null;
        ResultSet goldenCascadeRows = null;
        try {
            goldenCascadeStatement = goldenCascadeConnection.createStatement();
            goldenCascadeRows = goldenCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenCascadeRows.getRow());
        } finally {
            if (goldenCascadeRows != null) {
                goldenCascadeRows.close();
            }
            if (goldenCascadeStatement != null) {
                goldenCascadeStatement.close();
            }
            goldenCascadeConnection.close();
        }
    }

    public void runGoldenCascade() throws SQLException {
        String data;
        data = "foo";
        queryGoldenCascade(data);
    }
}
