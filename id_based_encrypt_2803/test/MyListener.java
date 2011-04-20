
import org.junit.runner.Description;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author foxneig
 */
class MyListener extends RunListener {

    @Override
    public void testStarted(Description desc)
    {
        System.out.println("Started:" + desc.getDisplayName());
    }

    @Override
    public void testFinished(Description desc)
    {
        System.out.println("Finished:" + desc.getDisplayName());

    }

    @Override
    public void testFailure(Failure fail)
    {
        System.out.println("Failed:" + fail.getDescription().getDisplayName() + " [" + fail.
                getMessage() + "]");
    }
}
