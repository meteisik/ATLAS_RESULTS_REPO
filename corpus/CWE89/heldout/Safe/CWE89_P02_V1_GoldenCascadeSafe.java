import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_GoldenCascadeSafe {

    public void runGoldenCascade() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
    }
}
